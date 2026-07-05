//! Rollout-oriented runtime extensions.
//!
//! This module is the public boundary for filesystem state primitives
//! and direct step execution. The OCI lifecycle remains exported from
//! the crate root.

pub use crate::runtime::{cmd_exec_rollout, RolloutExecOpts};

use crate::runtime::{is_init_alive, read_bundle, read_status_pid_comm};
use crate::spec::Spec;
use crate::state::{write_state, ContainerPaths};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct OverlayRootfs {
    pub(crate) lowerdirs: Vec<PathBuf>,
    pub(crate) upperdir: PathBuf,
    pub(crate) workdir: PathBuf,
    pub(crate) merged: PathBuf,
}

pub(crate) fn prepare_overlay_rootfs(
    paths: &ContainerPaths,
    spec: &Spec,
) -> std::io::Result<Option<OverlayRootfs>> {
    let Some(cfg) = spec.rootfs_backend.as_ref() else {
        return Ok(None);
    };
    if cfg.backend != "overlayfs" {
        return Err(std::io::Error::other(format!(
            "rootfs backend {} is not supported",
            cfg.backend
        )));
    }
    let overlay = overlay_paths(paths, spec)?;
    validate_overlay_paths(paths, &overlay)?;
    std::fs::create_dir_all(&overlay.upperdir)?;
    std::fs::create_dir_all(&overlay.workdir)?;
    std::fs::create_dir_all(&overlay.merged)?;
    mount_overlay(&overlay)?;
    Ok(Some(overlay))
}

fn overlay_paths(paths: &ContainerPaths, spec: &Spec) -> std::io::Result<OverlayRootfs> {
    let cfg = spec
        .rootfs_backend
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing rootfs backend"))?;
    let base = paths.root.join("overlay");
    let lowerdir = resolve_bundle_path(
        &spec.bundle,
        cfg.lowerdir.as_deref().unwrap_or(&spec.root_path),
    )?;
    let upperdir = resolve_state_path(paths, cfg.upperdir.as_deref(), &base.join("upper"));
    let workdir = resolve_state_path(paths, cfg.workdir.as_deref(), &base.join("work"));
    let merged = resolve_state_path(paths, cfg.merged.as_deref(), &base.join("merged"));
    Ok(OverlayRootfs {
        lowerdirs: vec![lowerdir],
        upperdir,
        workdir,
        merged,
    })
}

fn resolve_bundle_path(bundle: &Path, path: &Path) -> std::io::Result<PathBuf> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        bundle.join(path)
    };
    candidate.canonicalize()
}

fn resolve_state_path(
    paths: &ContainerPaths,
    configured: Option<&Path>,
    default: &Path,
) -> PathBuf {
    match configured {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => paths.root.join(path),
        None => default.to_path_buf(),
    }
}

fn validate_overlay_paths(paths: &ContainerPaths, overlay: &OverlayRootfs) -> std::io::Result<()> {
    if overlay.lowerdirs.is_empty() {
        return Err(std::io::Error::other("overlay lowerdir chain is empty"));
    }
    for lowerdir in &overlay.lowerdirs {
        if !lowerdir.is_dir() {
            return Err(std::io::Error::other(format!(
                "overlay lowerdir {} is not a directory",
                lowerdir.display()
            )));
        }
        reject_overlay_lowerdir_chars(lowerdir)?;
    }
    for path in [&overlay.upperdir, &overlay.workdir, &overlay.merged] {
        reject_overlay_option_chars(path)?;
    }
    let root = absolute_lexical(&paths.root)?;
    for (name, path) in [
        ("upperdir", &overlay.upperdir),
        ("workdir", &overlay.workdir),
        ("merged", &overlay.merged),
    ] {
        let path_abs = absolute_lexical(path)?;
        if !path_abs.starts_with(&root) {
            return Err(std::io::Error::other(format!(
                "overlay {name} must be under rsrun state directory {}",
                root.display()
            )));
        }
    }
    if overlay.upperdir == overlay.workdir
        || overlay.upperdir == overlay.merged
        || overlay.workdir == overlay.merged
    {
        return Err(std::io::Error::other(
            "overlay upperdir, workdir, and merged must be distinct",
        ));
    }
    Ok(())
}

fn absolute_lexical(path: &Path) -> std::io::Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut out = PathBuf::new();
    for component in abs.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                out.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::ParentDir => {
                if !out.pop() {
                    return Err(std::io::Error::other(format!(
                        "path {} escapes its root",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(out)
}

fn reject_overlay_option_chars(path: &Path) -> std::io::Result<()> {
    let s = path.as_os_str().to_string_lossy();
    if s.contains(',') || s.contains('\n') || s.contains('\0') {
        return Err(std::io::Error::other(format!(
            "overlay path {} contains an unsupported character",
            path.display()
        )));
    }
    Ok(())
}

fn reject_overlay_lowerdir_chars(path: &Path) -> std::io::Result<()> {
    reject_overlay_option_chars(path)?;
    let s = path.as_os_str().to_string_lossy();
    if s.contains(':') {
        return Err(std::io::Error::other(format!(
            "overlay lowerdir {} contains ':' which is unsupported by this mount path",
            path.display()
        )));
    }
    Ok(())
}

fn mount_overlay(overlay: &OverlayRootfs) -> std::io::Result<()> {
    let lowerdir = overlay
        .lowerdirs
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(":");
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdir,
        overlay.upperdir.display(),
        overlay.workdir.display()
    );
    mount(
        Some("overlay"),
        &overlay.merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(data.as_str()),
    )
    .map_err(std::io::Error::other)
}

pub(crate) fn write_overlay_state(
    paths: &ContainerPaths,
    overlay: &OverlayRootfs,
    reset_count: u64,
) -> std::io::Result<()> {
    let value = serde_json::json!({
        "backend": "overlayfs",
        "lowerdir": overlay.lowerdirs.first(),
        "lowerdirs": &overlay.lowerdirs,
        "upperdir": overlay.upperdir,
        "workdir": overlay.workdir,
        "merged": overlay.merged,
        "resetCount": reset_count,
    });
    std::fs::write(paths.root.join("overlay.json"), serde_json::to_vec(&value)?)
}

fn read_overlay_state(paths: &ContainerPaths) -> std::io::Result<(OverlayRootfs, u64)> {
    let bytes = std::fs::read(paths.root.join("overlay.json"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value.get("backend").and_then(|v| v.as_str()) != Some("overlayfs") {
        return Err(std::io::Error::other("container is not overlayfs-backed"));
    }
    let path = |key: &str| -> std::io::Result<PathBuf> {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .ok_or_else(|| std::io::Error::other(format!("overlay metadata missing {key}")))
    };
    let lowerdirs = match value.get("lowerdirs").and_then(|v| v.as_array()) {
        Some(values) => values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(PathBuf::from)
                    .ok_or_else(|| std::io::Error::other("overlay metadata has invalid lowerdirs"))
            })
            .collect::<std::io::Result<Vec<_>>>()?,
        None => vec![path("lowerdir")?],
    };
    let overlay = OverlayRootfs {
        lowerdirs,
        upperdir: path("upperdir")?,
        workdir: path("workdir")?,
        merged: path("merged")?,
    };
    validate_overlay_paths(paths, &overlay)?;
    Ok((
        overlay,
        value
            .get("resetCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    ))
}

pub(crate) fn cleanup_overlay_rootfs(paths: &ContainerPaths) -> std::io::Result<()> {
    let Ok((overlay, _)) = read_overlay_state(paths) else {
        return Ok(());
    };
    unmount_overlay(&overlay)
}

pub(crate) fn unmount_overlay(overlay: &OverlayRootfs) -> std::io::Result<()> {
    match umount2(&overlay.merged, MntFlags::MNT_DETACH) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::EINVAL) | Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(e) => Err(std::io::Error::other(e)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiffKind {
    Added,
    Modified,
    Deleted,
    OpaqueDir,
}

impl DiffKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
            Self::OpaqueDir => "opaque_dir",
        }
    }
}

#[derive(Debug, Clone)]
struct DiffEntry {
    path: String,
    kind: DiffKind,
    file_type: String,
    size: Option<u64>,
    lower_size: Option<u64>,
    size_delta: Option<i64>,
    sensitive: bool,
    fingerprint: String,
    upper_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MarkEntry {
    path: String,
    kind: String,
    sensitive: bool,
    size: Option<u64>,
    fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectEntry {
    path: String,
    before: Option<String>,
    after: Option<String>,
    sensitive: bool,
    bytes_written: u64,
}

pub fn cmd_changed_files(id: &str, json: bool) -> std::io::Result<()> {
    let paths = ContainerPaths::for_id(id);
    let (overlay, _) = read_overlay_state(&paths)?;
    let entries = scan_overlay_diff(&overlay)?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&changed_files_json(id, &entries))?
        );
    } else {
        for entry in &entries {
            println!("{}\t{}", entry.kind.as_str(), entry.path);
        }
    }
    Ok(())
}

pub fn cmd_diff(id: &str, json: bool) -> std::io::Result<()> {
    let paths = ContainerPaths::for_id(id);
    let (overlay, _) = read_overlay_state(&paths)?;
    let entries = scan_overlay_diff(&overlay)?;
    if json {
        println!("{}", serde_json::to_string(&diff_json(id, &entries))?);
    } else {
        for entry in &entries {
            println!(
                "{}\t{}\t{}",
                entry.kind.as_str(),
                entry.file_type,
                entry.path
            );
        }
    }
    Ok(())
}

pub fn cmd_export_diff(id: &str, format: &str) -> std::io::Result<()> {
    let paths = ContainerPaths::for_id(id);
    let (overlay, _) = read_overlay_state(&paths)?;
    let entries = scan_overlay_diff(&overlay)?;
    match format {
        "json" => {
            println!("{}", serde_json::to_string(&diff_json(id, &entries))?);
            Ok(())
        }
        "tar" => {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            write_overlay_tar(&mut out, &entries)
        }
        "patch" => Err(std::io::Error::other(
            "export-diff --format patch is not implemented; use tar or json",
        )),
        other => Err(std::io::Error::other(format!(
            "unsupported export-diff format {other}; expected tar, json, or patch"
        ))),
    }
}

pub fn cmd_mark(id: &str, name: &str) -> std::io::Result<()> {
    validate_state_name(name, "marker name")?;
    let paths = ContainerPaths::for_id(id);
    let (overlay, reset_count) = read_overlay_state(&paths)?;
    let entries = scan_overlay_diff(&overlay)?;
    write_marker(&paths, id, name, reset_count, &entries)?;
    Ok(())
}

pub fn cmd_effects(id: &str, since: &str, json: bool) -> std::io::Result<()> {
    validate_state_name(since, "marker name")?;
    let paths = ContainerPaths::for_id(id);
    let (overlay, reset_count) = read_overlay_state(&paths)?;
    let marker = read_marker(&paths, since)?;
    let marker_reset_count = marker
        .get("resetCount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| std::io::Error::other("marker metadata missing resetCount"))?;
    if marker_reset_count != reset_count {
        return Err(std::io::Error::other(format!(
            "marker {since} was created before reset count {reset_count}; create a new marker"
        )));
    }
    let marked = marker_entries_from_json(&marker)?;
    let current = marker_entries_from_diff(&scan_overlay_diff(&overlay)?);
    let effects = effects_since(&marked, &current);
    if json {
        println!(
            "{}",
            serde_json::to_string(&effects_json(id, since, &effects))?
        );
    } else {
        for entry in &effects {
            let before = entry.before.as_deref().unwrap_or("-");
            let after = entry.after.as_deref().unwrap_or("-");
            println!("{before}->{after}\t{}", entry.path);
        }
    }
    Ok(())
}

pub fn cmd_snapshot(id: &str, snapshot_id: &str) -> std::io::Result<()> {
    validate_state_name(snapshot_id, "snapshot id")?;
    let paths = ContainerPaths::for_id(id);
    ensure_stopped_for_fs_state(id, &paths, "snapshot")?;
    let (overlay, reset_count) = read_overlay_state(&paths)?;
    let bundle = read_bundle(&paths).unwrap_or_default();
    let snapshot = snapshot_paths(snapshot_id)?;
    if snapshot.root.exists() {
        return Err(std::io::Error::other(format!(
            "snapshot {snapshot_id} already exists"
        )));
    }
    let stats = enforce_snapshot_limits(&overlay.upperdir)?;
    std::fs::create_dir_all(&snapshot.root)?;
    if let Err(e) = clone_upperdir(&overlay.upperdir, &snapshot.upper) {
        let _ = std::fs::remove_dir_all(&snapshot.root);
        return Err(e);
    }
    let meta = serde_json::json!({
        "version": 1,
        "backend": "overlayfs",
        "id": snapshot_id,
        "source_id": id,
        "lowerdir": overlay.lowerdirs.first(),
        "lowerdirs": &overlay.lowerdirs,
        "bundle": bundle,
        "resetCount": reset_count,
        "entries": stats.entries,
        "bytes": stats.bytes,
    });
    std::fs::write(snapshot.meta, serde_json::to_vec(&meta)?)?;
    Ok(())
}

pub fn cmd_restore(snapshot_id: &str, new_id: &str, json: bool) -> std::io::Result<()> {
    validate_state_name(snapshot_id, "snapshot id")?;
    validate_state_name(new_id, "container id")?;
    let snapshot = snapshot_paths(snapshot_id)?;
    let meta = read_snapshot_meta(&snapshot)?;
    let paths = ContainerPaths::for_id(new_id);
    if paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {new_id} already exists"
        )));
    }
    restore_snapshot_into(&snapshot, &meta, new_id, &paths)?;
    if json {
        let out = serde_json::json!({
            "id": new_id,
            "snapshot": snapshot_id,
            "backend": "overlayfs",
            "restored": true,
            "merged": paths.root.join("overlay/merged"),
        });
        println!("{}", serde_json::to_string(&out)?);
    }
    Ok(())
}

pub fn cmd_fork(id: &str, new_id: &str, json: bool) -> std::io::Result<()> {
    validate_state_name(new_id, "container id")?;
    let source_paths = ContainerPaths::for_id(id);
    ensure_stopped_for_fs_state(id, &source_paths, "fork")?;
    let (source, reset_count) = read_overlay_state(&source_paths)?;
    let bundle = read_bundle(&source_paths).unwrap_or_default();
    let target_paths = ContainerPaths::for_id(new_id);
    if target_paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {new_id} already exists"
        )));
    }
    target_paths.ensure()?;
    let target = OverlayRootfs {
        lowerdirs: source.lowerdirs.clone(),
        upperdir: target_paths.root.join("overlay/upper"),
        workdir: target_paths.root.join("overlay/work"),
        merged: target_paths.root.join("overlay/merged"),
    };
    let result: std::io::Result<()> = (|| {
        enforce_snapshot_limits(&source.upperdir)?;
        clone_upperdir(&source.upperdir, &target.upperdir)?;
        std::fs::create_dir_all(&target.workdir)?;
        std::fs::create_dir_all(&target.merged)?;
        validate_overlay_paths(&target_paths, &target)?;
        mount_overlay(&target)?;
        write_overlay_state(&target_paths, &target, reset_count)?;
        write_state(&target_paths, new_id, 0, &bundle, "stopped", None)?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = unmount_overlay(&target);
        let _ = target_paths.destroy();
        return Err(e);
    }
    if json {
        let out = serde_json::json!({
            "id": new_id,
            "source": id,
            "backend": "overlayfs",
            "forked": true,
            "merged": target.merged,
        });
        println!("{}", serde_json::to_string(&out)?);
    }
    Ok(())
}

pub fn cmd_checkpoint(id: &str, checkpoint_id: &str, json: bool) -> std::io::Result<()> {
    validate_state_name(checkpoint_id, "checkpoint id")?;
    let paths = ContainerPaths::for_id(id);
    ensure_checkpoint_quiescent(id, &paths)?;
    let (overlay, reset_count) = read_overlay_state(&paths)?;
    let bundle = read_bundle(&paths).unwrap_or_default();
    let checkpoint = checkpoint_paths(checkpoint_id)?;
    if checkpoint.root.exists() {
        return Err(std::io::Error::other(format!(
            "checkpoint {checkpoint_id} already exists"
        )));
    }
    let stats = enforce_snapshot_limits(&overlay.upperdir)?;
    std::fs::create_dir_all(&checkpoint.root)?;
    if let Err(e) = clone_upperdir(&overlay.upperdir, &checkpoint.layer) {
        let _ = std::fs::remove_dir_all(&checkpoint.root);
        return Err(e);
    }
    if let Err(e) = make_tree_readonly(&checkpoint.layer) {
        let _ = std::fs::remove_dir_all(&checkpoint.root);
        return Err(e);
    }
    let mut lowerdirs = Vec::with_capacity(overlay.lowerdirs.len() + 1);
    lowerdirs.push(checkpoint.layer.clone());
    lowerdirs.extend(overlay.lowerdirs.iter().cloned());
    let meta = serde_json::json!({
        "version": 1,
        "kind": "checkpoint",
        "backend": "overlayfs",
        "id": checkpoint_id,
        "source_id": id,
        "bundle": bundle,
        "resetCount": reset_count,
        "entries": stats.entries,
        "bytes": stats.bytes,
        "layer": &checkpoint.layer,
        "lowerdirs": &lowerdirs,
        "parent_lowerdirs": &overlay.lowerdirs,
        "layers": [{
            "backend": "overlayfs",
            "format": "overlay-upperdir",
            "store": "local-directory",
            "path": &checkpoint.layer,
        }],
    });
    std::fs::write(&checkpoint.meta, serde_json::to_vec(&meta)?)?;
    if json {
        let out = serde_json::json!({
            "id": checkpoint_id,
            "source": id,
            "backend": "overlayfs",
            "checkpointed": true,
            "layer": &checkpoint.layer,
            "lowerdirs": &lowerdirs,
            "entries": stats.entries,
            "bytes": stats.bytes,
        });
        println!("{}", serde_json::to_string(&out)?);
    }
    Ok(())
}

pub fn cmd_fork_checkpoint(checkpoint_id: &str, new_id: &str, json: bool) -> std::io::Result<()> {
    validate_state_name(checkpoint_id, "checkpoint id")?;
    validate_state_name(new_id, "container id")?;
    let checkpoint = checkpoint_paths(checkpoint_id)?;
    let meta = read_checkpoint_meta(&checkpoint)?;
    let paths = ContainerPaths::for_id(new_id);
    if paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {new_id} already exists"
        )));
    }
    paths.ensure()?;
    let overlay = OverlayRootfs {
        lowerdirs: meta.lowerdirs.clone(),
        upperdir: paths.root.join("overlay/upper"),
        workdir: paths.root.join("overlay/work"),
        merged: paths.root.join("overlay/merged"),
    };
    let result: std::io::Result<()> = (|| {
        std::fs::create_dir_all(&overlay.upperdir)?;
        std::fs::create_dir_all(&overlay.workdir)?;
        std::fs::create_dir_all(&overlay.merged)?;
        validate_overlay_paths(&paths, &overlay)?;
        mount_overlay(&overlay)?;
        write_overlay_state(&paths, &overlay, meta.reset_count)?;
        write_state(&paths, new_id, 0, &meta.bundle, "stopped", None)?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = unmount_overlay(&overlay);
        let _ = paths.destroy();
        return Err(e);
    }
    if json {
        let out = serde_json::json!({
            "id": new_id,
            "checkpoint": checkpoint_id,
            "backend": "overlayfs",
            "forked": true,
            "merged": &overlay.merged,
            "upperdir": &overlay.upperdir,
            "lowerdirs": &overlay.lowerdirs,
        });
        println!("{}", serde_json::to_string(&out)?);
    }
    Ok(())
}

struct SnapshotPaths {
    root: PathBuf,
    upper: PathBuf,
    meta: PathBuf,
}

struct CheckpointPaths {
    root: PathBuf,
    layer: PathBuf,
    meta: PathBuf,
}

struct SnapshotMeta {
    lowerdirs: Vec<PathBuf>,
    bundle: PathBuf,
    reset_count: u64,
}

struct CheckpointMeta {
    lowerdirs: Vec<PathBuf>,
    bundle: PathBuf,
    reset_count: u64,
}

fn snapshot_paths(snapshot_id: &str) -> std::io::Result<SnapshotPaths> {
    let base = runtime_root_dir()?.join(".snapshots").join(snapshot_id);
    Ok(SnapshotPaths {
        upper: base.join("upper"),
        meta: base.join("meta.json"),
        root: base,
    })
}

fn checkpoint_paths(checkpoint_id: &str) -> std::io::Result<CheckpointPaths> {
    let base = runtime_root_dir()?.join(".checkpoints").join(checkpoint_id);
    Ok(CheckpointPaths {
        layer: base.join("layer"),
        meta: base.join("meta.json"),
        root: base,
    })
}

fn runtime_root_dir() -> std::io::Result<PathBuf> {
    let dummy = ContainerPaths::for_id("__rsrun_root__");
    dummy
        .root
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("invalid runtime root"))
}

fn read_snapshot_meta(paths: &SnapshotPaths) -> std::io::Result<SnapshotMeta> {
    let bytes = std::fs::read(&paths.meta)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value.get("backend").and_then(|v| v.as_str()) != Some("overlayfs") {
        return Err(std::io::Error::other("snapshot is not overlayfs-backed"));
    }
    let lowerdirs = match value.get("lowerdirs").and_then(|v| v.as_array()) {
        Some(values) => values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(PathBuf::from)
                    .ok_or_else(|| std::io::Error::other("snapshot metadata has invalid lowerdirs"))
            })
            .collect::<std::io::Result<Vec<_>>>()?,
        None => {
            let lowerdir = value
                .get("lowerdir")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .ok_or_else(|| std::io::Error::other("snapshot metadata missing lowerdir"))?;
            vec![lowerdir]
        }
    };
    let bundle = value
        .get("bundle")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_default();
    for lowerdir in &lowerdirs {
        if !lowerdir.is_dir() {
            return Err(std::io::Error::other(format!(
                "snapshot lowerdir {} is not available",
                lowerdir.display()
            )));
        }
    }
    Ok(SnapshotMeta {
        lowerdirs,
        bundle,
        reset_count: value
            .get("resetCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    })
}

fn read_checkpoint_meta(paths: &CheckpointPaths) -> std::io::Result<CheckpointMeta> {
    let bytes = std::fs::read(&paths.meta)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value.get("kind").and_then(|v| v.as_str()) != Some("checkpoint") {
        return Err(std::io::Error::other("metadata is not a checkpoint"));
    }
    if value.get("backend").and_then(|v| v.as_str()) != Some("overlayfs") {
        return Err(std::io::Error::other("checkpoint backend is not supported"));
    }
    let lowerdirs = value
        .get("lowerdirs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| std::io::Error::other("checkpoint metadata missing lowerdirs"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(PathBuf::from)
                .ok_or_else(|| std::io::Error::other("checkpoint metadata has invalid lowerdirs"))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    if lowerdirs.is_empty() {
        return Err(std::io::Error::other("checkpoint lowerdir chain is empty"));
    }
    for lowerdir in &lowerdirs {
        if !lowerdir.is_dir() {
            return Err(std::io::Error::other(format!(
                "checkpoint lowerdir {} is not available",
                lowerdir.display()
            )));
        }
    }
    let bundle = value
        .get("bundle")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_default();
    Ok(CheckpointMeta {
        lowerdirs,
        bundle,
        reset_count: value
            .get("resetCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    })
}

fn restore_snapshot_into(
    snapshot: &SnapshotPaths,
    meta: &SnapshotMeta,
    id: &str,
    paths: &ContainerPaths,
) -> std::io::Result<()> {
    paths.ensure()?;
    let overlay = OverlayRootfs {
        lowerdirs: meta.lowerdirs.clone(),
        upperdir: paths.root.join("overlay/upper"),
        workdir: paths.root.join("overlay/work"),
        merged: paths.root.join("overlay/merged"),
    };
    let result: std::io::Result<()> = (|| {
        enforce_snapshot_limits(&snapshot.upper)?;
        clone_upperdir(&snapshot.upper, &overlay.upperdir)?;
        std::fs::create_dir_all(&overlay.workdir)?;
        std::fs::create_dir_all(&overlay.merged)?;
        validate_overlay_paths(paths, &overlay)?;
        mount_overlay(&overlay)?;
        write_overlay_state(paths, &overlay, meta.reset_count)?;
        write_state(paths, id, 0, &meta.bundle, "stopped", None)?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = unmount_overlay(&overlay);
        let _ = paths.destroy();
        return Err(e);
    }
    Ok(())
}

fn ensure_checkpoint_quiescent(id: &str, paths: &ContainerPaths) -> std::io::Result<()> {
    if !paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} does not exist"
        )));
    }
    let (status, pid, comm) = read_status_pid_comm(paths);
    if pid > 0 && is_init_alive(pid, comm.as_deref()) {
        let st = status.as_deref().unwrap_or("creating");
        if st != "created" {
            return Err(std::io::Error::other(format!(
                "cannot checkpoint container {id} in state {st}; stop it first"
            )));
        }
    }
    Ok(())
}

fn ensure_stopped_for_fs_state(id: &str, paths: &ContainerPaths, op: &str) -> std::io::Result<()> {
    if !paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} does not exist"
        )));
    }
    let (status, pid, comm) = read_status_pid_comm(paths);
    if pid > 0 && is_init_alive(pid, comm.as_deref()) {
        let st = status.as_deref().unwrap_or("creating");
        return Err(std::io::Error::other(format!(
            "cannot {op} container {id} in state {st}; stop it first"
        )));
    }
    Ok(())
}

fn validate_state_name(name: &str, label: &str) -> std::io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(std::io::Error::other(format!("invalid {label}: {name}")));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct SnapshotStats {
    entries: u64,
    bytes: u64,
}

fn enforce_snapshot_limits(root: &Path) -> std::io::Result<SnapshotStats> {
    let stats = measure_upperdir(root)?;
    let max_bytes = snapshot_limit_env("RSRUN_SNAPSHOT_MAX_BYTES", 10 * 1024 * 1024 * 1024);
    let max_entries = snapshot_limit_env("RSRUN_SNAPSHOT_MAX_ENTRIES", 500_000);
    if max_bytes > 0 && stats.bytes > max_bytes {
        return Err(std::io::Error::other(format!(
            "snapshot upperdir has {} bytes, exceeds limit {}",
            stats.bytes, max_bytes
        )));
    }
    if max_entries > 0 && stats.entries > max_entries {
        return Err(std::io::Error::other(format!(
            "snapshot upperdir has {} entries, exceeds limit {}",
            stats.entries, max_entries
        )));
    }
    Ok(stats)
}

fn snapshot_limit_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn measure_upperdir(root: &Path) -> std::io::Result<SnapshotStats> {
    let mut stats = SnapshotStats {
        entries: 0,
        bytes: 0,
    };
    measure_upperdir_inner(root, &mut stats)?;
    Ok(stats)
}

fn measure_upperdir_inner(path: &Path, stats: &mut SnapshotStats) -> std::io::Result<()> {
    let mut entries = std::fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let child = entry.path();
        let meta = std::fs::symlink_metadata(&child)?;
        stats.entries = stats.entries.saturating_add(1);
        if meta.file_type().is_file() {
            stats.bytes = stats.bytes.saturating_add(meta.len());
        }
        if meta.file_type().is_dir() {
            measure_upperdir_inner(&child, stats)?;
        }
    }
    Ok(())
}

fn make_tree_readonly(root: &Path) -> std::io::Result<()> {
    let mut entries = std::fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let child = entry.path();
        let meta = std::fs::symlink_metadata(&child)?;
        if meta.file_type().is_dir() {
            make_tree_readonly(&child)?;
        }
        if !meta.file_type().is_symlink() {
            let mode = meta.mode() & !0o222;
            std::fs::set_permissions(&child, std::fs::Permissions::from_mode(mode))?;
        }
    }
    let meta = std::fs::symlink_metadata(root)?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(meta.mode() & !0o222))
}

fn clone_upperdir(src: &Path, dst: &Path) -> std::io::Result<()> {
    if dst.exists() {
        return Err(std::io::Error::other(format!(
            "destination {} already exists",
            dst.display()
        )));
    }
    std::fs::create_dir_all(dst)?;
    clone_dir_contents(src, dst)?;
    copy_metadata(src, dst)?;
    Ok(())
}

fn clone_dir_contents(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut entries = std::fs::read_dir(src)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        clone_path(&src_path, &dst_path)?;
    }
    Ok(())
}

fn clone_path(src: &Path, dst: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    let ft = meta.file_type();
    if ft.is_dir() {
        std::fs::create_dir(dst)?;
        clone_dir_contents(src, dst)?;
        copy_metadata(src, dst)?;
    } else if ft.is_file() {
        clone_regular_file(src, dst)?;
        copy_metadata(src, dst)?;
    } else if ft.is_symlink() {
        let target = std::fs::read_link(src)?;
        std::os::unix::fs::symlink(target, dst)?;
        copy_xattrs(src, dst)?;
        copy_owner(src, dst, &meta)?;
    } else if ft.is_socket() {
        return Ok(());
    } else if ft.is_char_device() || ft.is_block_device() || ft.is_fifo() {
        clone_special_file(dst, &meta)?;
        copy_metadata(src, dst)?;
    }
    Ok(())
}

fn clone_regular_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    let src_file = std::fs::File::open(src)?;
    let dst_file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dst)?;
    if reflink_file(&src_file, &dst_file).is_err() {
        std::io::copy(&mut &src_file, &mut &dst_file)?;
    }
    Ok(())
}

fn reflink_file(src: &std::fs::File, dst: &std::fs::File) -> std::io::Result<()> {
    const FICLONE: libc::c_ulong = 0x4004_9409;
    let rc = unsafe { libc::ioctl(dst.as_raw_fd(), FICLONE, src.as_raw_fd()) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn clone_special_file(dst: &Path, meta: &std::fs::Metadata) -> std::io::Result<()> {
    let path_c = CString::new(dst.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("path contains NUL"))?;
    let mode = meta.mode() as libc::mode_t;
    let rc = if meta.file_type().is_fifo() {
        unsafe { libc::mkfifo(path_c.as_ptr(), mode) }
    } else if meta.file_type().is_socket() {
        return Ok(());
    } else {
        unsafe { libc::mknod(path_c.as_ptr(), mode, meta.rdev()) }
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn copy_metadata(src: &Path, dst: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(meta.mode() & 0o7777))?;
    copy_owner(src, dst, &meta)?;
    copy_xattrs(src, dst)
}

fn copy_owner(_src: &Path, dst: &Path, meta: &std::fs::Metadata) -> std::io::Result<()> {
    let dst_c = CString::new(dst.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("path contains NUL"))?;
    let rc = unsafe { libc::lchown(dst_c.as_ptr(), meta.uid(), meta.gid()) };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EPERM) {
            return Err(e);
        }
    }
    Ok(())
}

fn copy_xattrs(src: &Path, dst: &Path) -> std::io::Result<()> {
    let names = list_xattrs(src)?;
    for name in names {
        let Some(value) = lgetxattr_value(src, &name) else {
            continue;
        };
        set_xattr(dst, &name, &value)?;
    }
    Ok(())
}

fn list_xattrs(path: &Path) -> std::io::Result<Vec<String>> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("path contains NUL"))?;
    let len = unsafe { libc::llistxattr(path_c.as_ptr(), std::ptr::null_mut(), 0) };
    if len < 0 {
        let e = std::io::Error::last_os_error();
        if matches!(e.raw_os_error(), Some(libc::ENOTSUP) | Some(libc::ENODATA)) {
            return Ok(Vec::new());
        }
        return Err(e);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len as usize];
    let got = unsafe { libc::llistxattr(path_c.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) };
    if got < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    Ok(buf
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok().map(String::from))
        .collect())
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("path contains NUL"))?;
    let name_c = CString::new(name).map_err(|_| std::io::Error::other("xattr name has NUL"))?;
    let rc = unsafe {
        libc::lsetxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            value.as_ptr() as *const _,
            value.len(),
            0,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn scan_overlay_diff(overlay: &OverlayRootfs) -> std::io::Result<Vec<DiffEntry>> {
    let mut entries = Vec::new();
    if !overlay.upperdir.exists() {
        return Ok(entries);
    }
    scan_overlay_dir(overlay, Path::new(""), &mut entries)?;
    entries.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.kind.as_str().cmp(b.kind.as_str()))
    });
    Ok(entries)
}

fn scan_overlay_dir(
    overlay: &OverlayRootfs,
    rel_dir: &Path,
    entries: &mut Vec<DiffEntry>,
) -> std::io::Result<()> {
    let upper_dir = overlay.upperdir.join(rel_dir);
    let mut children = std::fs::read_dir(&upper_dir)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let name = child.file_name();
        let rel = rel_dir.join(&name);
        let upper = child.path();
        let meta = std::fs::symlink_metadata(&upper)?;
        let lower_meta = lower_metadata(overlay, &rel)?;
        if is_overlay_whiteout(&upper, &meta) {
            entries.push(diff_entry(
                overlay,
                rel.as_path(),
                DiffKind::Deleted,
                "whiteout",
                &meta,
                lower_meta.as_ref(),
                false,
            ));
            continue;
        }

        let kind = if lower_meta.is_some() {
            DiffKind::Modified
        } else {
            DiffKind::Added
        };
        let file_type = file_type_name(&meta);
        entries.push(diff_entry(
            overlay,
            rel.as_path(),
            kind,
            &file_type,
            &meta,
            lower_meta.as_ref(),
            true,
        ));

        if meta.file_type().is_dir() {
            if is_overlay_opaque_dir(&upper) {
                entries.push(diff_entry(
                    overlay,
                    rel.as_path(),
                    DiffKind::OpaqueDir,
                    "directory",
                    &meta,
                    lower_meta.as_ref(),
                    true,
                ));
            }
            scan_overlay_dir(overlay, rel.as_path(), entries)?;
        }
    }
    Ok(())
}

fn lower_metadata(
    overlay: &OverlayRootfs,
    rel: &Path,
) -> std::io::Result<Option<std::fs::Metadata>> {
    for lowerdir in &overlay.lowerdirs {
        if lower_hides_path(lowerdir, rel)? {
            return Ok(None);
        }
        let lower = lowerdir.join(rel);
        let Ok(meta) = std::fs::symlink_metadata(&lower) else {
            continue;
        };
        if is_overlay_whiteout(&lower, &meta) {
            return Ok(None);
        }
        return Ok(Some(meta));
    }
    Ok(None)
}

fn lower_hides_path(lowerdir: &Path, rel: &Path) -> std::io::Result<bool> {
    let mut ancestor = PathBuf::new();
    for component in rel.parent().into_iter().flat_map(Path::components) {
        let std::path::Component::Normal(part) = component else {
            continue;
        };
        ancestor.push(part);
        let path = lowerdir.join(&ancestor);
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_dir() && is_overlay_opaque_dir(&path) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn diff_entry(
    overlay: &OverlayRootfs,
    rel: &Path,
    kind: DiffKind,
    file_type: &str,
    meta: &std::fs::Metadata,
    lower_meta: Option<&std::fs::Metadata>,
    include_upper: bool,
) -> DiffEntry {
    let path = slash_path(rel);
    let size = if meta.file_type().is_file() {
        Some(meta.len())
    } else {
        None
    };
    let lower_size = lower_meta.and_then(|m| {
        if m.file_type().is_file() {
            Some(m.len())
        } else {
            None
        }
    });
    let size_delta = match (size, lower_size) {
        (Some(a), Some(b)) => Some(a as i64 - b as i64),
        (Some(a), None) => Some(a as i64),
        (None, Some(b)) if matches!(kind, DiffKind::Deleted) => Some(-(b as i64)),
        _ => None,
    };
    DiffEntry {
        upper_path: include_upper.then(|| overlay.upperdir.join(rel)),
        sensitive: is_sensitive_path(&path),
        path,
        kind,
        file_type: file_type.to_string(),
        size,
        lower_size,
        size_delta,
        fingerprint: diff_fingerprint(file_type, meta),
    }
}

fn diff_fingerprint(file_type: &str, meta: &std::fs::Metadata) -> String {
    format!(
        "type={file_type}:mode={:o}:uid={}:gid={}:rdev={}:size={}:mtime={}.{}:ctime={}.{}",
        meta.mode(),
        meta.uid(),
        meta.gid(),
        meta.rdev(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec()
    )
}

fn changed_files_json(id: &str, entries: &[DiffEntry]) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "backend": "overlayfs",
        "files": entries.iter().map(|e| {
            serde_json::json!({
                "path": e.path,
                "kind": e.kind.as_str(),
                "sensitive": e.sensitive,
            })
        }).collect::<Vec<_>>(),
    })
}

fn diff_json(id: &str, entries: &[DiffEntry]) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "backend": "overlayfs",
        "files": entries.iter().map(|e| {
            serde_json::json!({
                "path": e.path,
                "kind": e.kind.as_str(),
                "file_type": e.file_type,
                "size": e.size,
                "lower_size": e.lower_size,
                "size_delta": e.size_delta,
                "sensitive": e.sensitive,
            })
        }).collect::<Vec<_>>(),
    })
}

fn marker_path(paths: &ContainerPaths, name: &str) -> PathBuf {
    paths.root.join("markers").join(format!("{name}.json"))
}

fn write_marker(
    paths: &ContainerPaths,
    id: &str,
    name: &str,
    reset_count: u64,
    entries: &[DiffEntry],
) -> std::io::Result<()> {
    let marker_dir = paths.root.join("markers");
    std::fs::create_dir_all(&marker_dir)?;
    let value = serde_json::json!({
        "version": 1,
        "id": id,
        "name": name,
        "backend": "overlayfs",
        "resetCount": reset_count,
        "files": marker_entries_from_diff(entries).iter().map(|e| {
            serde_json::json!({
                "path": e.path,
                "kind": e.kind,
                "sensitive": e.sensitive,
                "size": e.size,
                "fingerprint": e.fingerprint,
            })
        }).collect::<Vec<_>>(),
    });
    std::fs::write(marker_path(paths, name), serde_json::to_vec(&value)?)
}

fn read_marker(paths: &ContainerPaths, name: &str) -> std::io::Result<serde_json::Value> {
    let bytes = std::fs::read(marker_path(paths, name))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value.get("backend").and_then(|v| v.as_str()) != Some("overlayfs") {
        return Err(std::io::Error::other("marker is not overlayfs-backed"));
    }
    Ok(value)
}

fn marker_entries_from_json(value: &serde_json::Value) -> std::io::Result<Vec<MarkEntry>> {
    let files = value
        .get("files")
        .and_then(|v| v.as_array())
        .ok_or_else(|| std::io::Error::other("marker metadata missing files"))?;
    files
        .iter()
        .map(|file| {
            let field = |name: &str| -> std::io::Result<String> {
                file.get(name)
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .ok_or_else(|| std::io::Error::other(format!("marker file missing {name}")))
            };
            Ok(MarkEntry {
                path: field("path")?,
                kind: field("kind")?,
                sensitive: file
                    .get("sensitive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                size: file.get("size").and_then(|v| v.as_u64()),
                fingerprint: field("fingerprint")?,
            })
        })
        .collect()
}

fn marker_entries_from_diff(entries: &[DiffEntry]) -> Vec<MarkEntry> {
    entries
        .iter()
        .map(|entry| MarkEntry {
            path: entry.path.clone(),
            kind: entry.kind.as_str().to_string(),
            sensitive: entry.sensitive,
            size: entry.size,
            fingerprint: entry.fingerprint.clone(),
        })
        .collect()
}

fn effects_since(marked: &[MarkEntry], current: &[MarkEntry]) -> Vec<EffectEntry> {
    let marked = marker_entry_map(marked);
    let current = marker_entry_map(current);
    let mut keys = BTreeSet::new();
    keys.extend(marked.keys().cloned());
    keys.extend(current.keys().cloned());

    let mut effects = Vec::new();
    for key in keys {
        let before = marked.get(&key);
        let after = current.get(&key);
        if before.map(|e| &e.fingerprint) == after.map(|e| &e.fingerprint) {
            continue;
        }
        let path = after
            .or(before)
            .map(|e| e.path.clone())
            .unwrap_or_else(|| key.clone());
        let sensitive = before.map(|e| e.sensitive).unwrap_or(false)
            || after.map(|e| e.sensitive).unwrap_or(false);
        effects.push(EffectEntry {
            path,
            before: before.map(|e| e.kind.clone()),
            after: after.map(|e| e.kind.clone()),
            sensitive,
            bytes_written: after.and_then(|e| e.size).unwrap_or(0),
        });
    }
    effects.sort_by(|a, b| a.path.cmp(&b.path).then(a.after.cmp(&b.after)));
    effects
}

fn marker_entry_map(entries: &[MarkEntry]) -> BTreeMap<String, MarkEntry> {
    entries
        .iter()
        .map(|entry| (format!("{}\0{}", entry.path, entry.kind), entry.clone()))
        .collect()
}

fn effects_json(id: &str, since: &str, effects: &[EffectEntry]) -> serde_json::Value {
    let mut changed_files = effects
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    changed_files.sort();
    changed_files.dedup();
    serde_json::json!({
        "id": id,
        "backend": "overlayfs",
        "since": since,
        "persistent_fs_change": !effects.is_empty(),
        "changed_files": changed_files,
        "files": effects.iter().map(|e| {
            serde_json::json!({
                "path": e.path,
                "before": e.before,
                "after": e.after,
                "sensitive": e.sensitive,
                "bytes_written": e.bytes_written,
            })
        }).collect::<Vec<_>>(),
        "sensitive_path_touched": effects.iter().any(|e| e.sensitive),
        "processes_spawned": serde_json::Value::Null,
        "network_used": serde_json::Value::Null,
        "bytes_written": effects.iter().map(|e| e.bytes_written).sum::<u64>(),
    })
}

fn file_type_name(meta: &std::fs::Metadata) -> String {
    let ft = meta.file_type();
    if ft.is_dir() {
        "directory"
    } else if ft.is_file() {
        "file"
    } else if ft.is_symlink() {
        "symlink"
    } else if ft.is_char_device() {
        "char_device"
    } else if ft.is_block_device() {
        "block_device"
    } else if ft.is_fifo() {
        "fifo"
    } else if ft.is_socket() {
        "socket"
    } else {
        "other"
    }
    .to_string()
}

fn is_overlay_whiteout(path: &Path, meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_char_device()
        && libc::major(meta.rdev()) == 0
        && libc::minor(meta.rdev()) == 0
    {
        return true;
    }
    meta.file_type().is_file()
        && meta.len() == 0
        && lgetxattr_value(path, "trusted.overlay.whiteout")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
}

fn is_overlay_opaque_dir(path: &Path) -> bool {
    matches!(
        lgetxattr_value(path, "trusted.overlay.opaque").as_deref(),
        Some(b"y") | Some(b"x")
    )
}

fn lgetxattr_value(path: &Path, name: &str) -> Option<Vec<u8>> {
    let path_c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let name_c = CString::new(name).ok()?;
    let len = unsafe { libc::lgetxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0) };
    if len <= 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    let got = unsafe {
        libc::lgetxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            buf.len(),
        )
    };
    if got < 0 {
        return None;
    }
    buf.truncate(got as usize);
    Some(buf)
}

fn is_sensitive_path(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    p == "etc/passwd"
        || p == "etc/shadow"
        || p == "etc/sudoers"
        || p.starts_with("root/.ssh/")
        || p.contains("/.ssh/")
        || p.ends_with(".pem")
        || p.ends_with(".key")
        || p.contains("id_rsa")
        || p.contains("id_ed25519")
        || p.contains("token")
        || p.contains("credential")
}

fn slash_path(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn write_overlay_tar<W: Write>(out: &mut W, entries: &[DiffEntry]) -> std::io::Result<()> {
    for entry in entries {
        match entry.kind {
            DiffKind::Deleted => {
                let wh = tar_whiteout_path(&entry.path);
                write_tar_empty_file(out, &wh, 0o000)?;
            }
            DiffKind::OpaqueDir => {
                let opq = if entry.path.is_empty() {
                    ".wh..wh..opq".to_string()
                } else {
                    format!("{}/.wh..wh..opq", entry.path)
                };
                write_tar_empty_file(out, &opq, 0o000)?;
            }
            DiffKind::Added | DiffKind::Modified => {
                let Some(path) = entry.upper_path.as_ref() else {
                    continue;
                };
                let meta = std::fs::symlink_metadata(path)?;
                write_tar_path(out, &entry.path, path, &meta)?;
            }
        }
    }
    out.write_all(&[0u8; 1024])?;
    Ok(())
}

fn tar_whiteout_path(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((dir, name)) => format!("{dir}/.wh.{name}"),
        None => format!(".wh.{path}"),
    }
}

fn write_tar_path<W: Write>(
    out: &mut W,
    name: &str,
    path: &Path,
    meta: &std::fs::Metadata,
) -> std::io::Result<()> {
    let ft = meta.file_type();
    let mode = meta.mode() & 0o7777;
    if ft.is_dir() {
        let mut name = name.to_string();
        if !name.ends_with('/') {
            name.push('/');
        }
        write_tar_header(out, &name, mode, 0, b'5', None)?;
    } else if ft.is_symlink() {
        let target = std::fs::read_link(path)?;
        write_tar_header(out, name, mode, 0, b'2', Some(&target.to_string_lossy()))?;
    } else if ft.is_file() {
        write_tar_header(out, name, mode, meta.len(), b'0', None)?;
        let mut file = std::fs::File::open(path)?;
        std::io::copy(&mut file, out)?;
        pad_tar(out, meta.len())?;
    }
    Ok(())
}

fn write_tar_empty_file<W: Write>(out: &mut W, name: &str, mode: u32) -> std::io::Result<()> {
    write_tar_header(out, name, mode, 0, b'0', None)
}

fn write_tar_header<W: Write>(
    out: &mut W,
    name: &str,
    mode: u32,
    size: u64,
    typeflag: u8,
    linkname: Option<&str>,
) -> std::io::Result<()> {
    let mut header = [0u8; 512];
    write_tar_name(&mut header, name)?;
    write_octal(&mut header[100..108], mode as u64);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size);
    write_octal(&mut header[136..148], 0);
    for b in &mut header[148..156] {
        *b = b' ';
    }
    header[156] = typeflag;
    if let Some(linkname) = linkname {
        write_bytes(&mut header[157..257], linkname.as_bytes())?;
    }
    write_bytes(&mut header[257..263], b"ustar\0")?;
    write_bytes(&mut header[263..265], b"00")?;
    let checksum: u32 = header.iter().map(|b| *b as u32).sum();
    write_octal(&mut header[148..156], checksum as u64);
    out.write_all(&header)
}

fn write_tar_name(header: &mut [u8; 512], name: &str) -> std::io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() <= 100 {
        write_bytes(&mut header[0..100], bytes)?;
        return Ok(());
    }
    if bytes.len() <= 255 {
        for split in (0..bytes.len()).rev() {
            if bytes[split] != b'/' {
                continue;
            }
            let prefix = &bytes[..split];
            let suffix = &bytes[split + 1..];
            if prefix.len() <= 155 && suffix.len() <= 100 {
                write_bytes(&mut header[0..100], suffix)?;
                write_bytes(&mut header[345..500], prefix)?;
                return Ok(());
            }
        }
    }
    Err(std::io::Error::other(format!(
        "tar path too long for ustar header: {name}"
    )))
}

fn write_bytes(dst: &mut [u8], src: &[u8]) -> std::io::Result<()> {
    if src.len() > dst.len() {
        return Err(std::io::Error::other("tar header field too long"));
    }
    dst[..src.len()].copy_from_slice(src);
    Ok(())
}

fn write_octal(dst: &mut [u8], value: u64) {
    for b in dst.iter_mut() {
        *b = 0;
    }
    let width = dst.len();
    let s = format!("{value:0width$o}", width = width - 1);
    let bytes = s.as_bytes();
    let start = width.saturating_sub(1 + bytes.len());
    dst[start..start + bytes.len()].copy_from_slice(bytes);
    dst[width - 1] = 0;
}

fn pad_tar<W: Write>(out: &mut W, size: u64) -> std::io::Result<()> {
    let pad = (512 - (size % 512)) % 512;
    if pad > 0 {
        out.write_all(&vec![0u8; pad as usize])?;
    }
    Ok(())
}

pub fn cmd_reset(id: &str, json: bool) -> std::io::Result<()> {
    let paths = ContainerPaths::for_id(id);
    if !paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} does not exist"
        )));
    }
    let (status, pid, comm) = read_status_pid_comm(&paths);
    if pid > 0 && is_init_alive(pid, comm.as_deref()) {
        let st = status.as_deref().unwrap_or("creating");
        return Err(std::io::Error::other(format!(
            "cannot reset container {id} in state {st}; stop it first"
        )));
    }

    let (overlay, reset_count) = read_overlay_state(&paths)?;
    cleanup_overlay_rootfs(&paths)?;
    if overlay.upperdir.exists() {
        std::fs::remove_dir_all(&overlay.upperdir)?;
    }
    if overlay.workdir.exists() {
        std::fs::remove_dir_all(&overlay.workdir)?;
    }
    std::fs::create_dir_all(&overlay.upperdir)?;
    std::fs::create_dir_all(&overlay.workdir)?;
    std::fs::create_dir_all(&overlay.merged)?;
    mount_overlay(&overlay)?;
    let reset_count = reset_count.saturating_add(1);
    write_overlay_state(&paths, &overlay, reset_count)?;

    if let Ok(bytes) = std::fs::read(paths.state_file()) {
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            value["status"] = serde_json::Value::String("stopped".to_string());
            value["rootfsResetCount"] = serde_json::Value::Number(reset_count.into());
            let _ = std::fs::write(paths.state_file(), serde_json::to_vec(&value)?);
        }
    }

    if json {
        let out = serde_json::json!({
            "id": id,
            "backend": "overlayfs",
            "reset": true,
            "resetCount": reset_count,
            "upperdir": overlay.upperdir,
            "workdir": overlay.workdir,
            "merged": overlay.merged,
        });
        println!("{}", serde_json::to_string(&out)?);
    }
    Ok(())
}

#[cfg(test)]
mod rollout_tests {
    use super::*;

    fn temp_state(name: &str) -> (PathBuf, ContainerPaths) {
        let root = std::env::temp_dir().join(format!(
            "rsrun-{name}-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let paths = ContainerPaths { root: root.clone() };
        (root, paths)
    }

    #[test]
    fn overlay_state_round_trips_paths_and_reset_count() {
        let (root, paths) = temp_state("overlay-state");
        let lower = root.join("lower");
        let overlay = OverlayRootfs {
            lowerdirs: vec![lower.clone()],
            upperdir: root.join("overlay/upper"),
            workdir: root.join("overlay/work"),
            merged: root.join("overlay/merged"),
        };
        std::fs::create_dir_all(&lower).unwrap();
        write_overlay_state(&paths, &overlay, 7).unwrap();

        let (read, reset_count) = read_overlay_state(&paths).unwrap();
        assert_eq!(reset_count, 7);
        assert_eq!(read.lowerdirs, overlay.lowerdirs);
        assert_eq!(read.upperdir, overlay.upperdir);
        assert_eq!(read.workdir, overlay.workdir);
        assert_eq!(read.merged, overlay.merged);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn overlay_state_rejects_reset_paths_outside_state_root() {
        let (root, paths) = temp_state("overlay-outside");
        let lower = root.join("lower");
        std::fs::create_dir_all(&lower).unwrap();
        let value = serde_json::json!({
            "backend": "overlayfs",
            "lowerdir": lower,
            "upperdir": "/tmp/rsrun-not-owned-upper",
            "workdir": root.join("overlay/work"),
            "merged": root.join("overlay/merged"),
            "resetCount": 0,
        });
        std::fs::write(
            paths.root.join("overlay.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();

        let err = read_overlay_state(&paths).unwrap_err();
        assert!(err.to_string().contains("must be under rsrun state"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn overlay_state_rejects_parent_dir_escape() {
        let (root, paths) = temp_state("overlay-parent-dir");
        let lower = root.join("lower");
        std::fs::create_dir_all(&lower).unwrap();
        let value = serde_json::json!({
            "backend": "overlayfs",
            "lowerdir": lower,
            "upperdir": root.join("../upper-escape"),
            "workdir": root.join("overlay/work"),
            "merged": root.join("overlay/merged"),
            "resetCount": 0,
        });
        std::fs::write(
            paths.root.join("overlay.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();

        let err = read_overlay_state(&paths).unwrap_err();
        assert!(err.to_string().contains("must be under rsrun state"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn scan_overlay_diff_reports_added_and_modified_from_upper_only() {
        let (root, _paths) = temp_state("overlay-diff");
        let lower = root.join("lower");
        let upper = root.join("upper");
        let work = root.join("work");
        let merged = root.join("merged");
        std::fs::create_dir_all(lower.join("etc")).unwrap();
        std::fs::create_dir_all(upper.join("etc")).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&merged).unwrap();
        std::fs::write(lower.join("etc/config"), b"old").unwrap();
        std::fs::write(upper.join("etc/config"), b"newer").unwrap();
        std::fs::write(upper.join("added"), b"hello").unwrap();

        let overlay = OverlayRootfs {
            lowerdirs: vec![lower],
            upperdir: upper,
            workdir: work,
            merged,
        };
        let entries = scan_overlay_diff(&overlay).unwrap();
        let added = entries.iter().find(|e| e.path == "added").unwrap();
        assert_eq!(added.kind, DiffKind::Added);
        assert_eq!(added.size_delta, Some(5));
        let modified = entries.iter().find(|e| e.path == "etc/config").unwrap();
        assert_eq!(modified.kind, DiffKind::Modified);
        assert_eq!(modified.size, Some(5));
        assert_eq!(modified.lower_size, Some(3));
        assert_eq!(modified.size_delta, Some(2));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn checkpoint_lower_chain_branches_keep_empty_independent_uppers() {
        let (root, _paths) = temp_state("checkpoint-lower-chain");
        let base = root.join("base");
        let checkpoint_1 = root.join("checkpoint-1/layer");
        let checkpoint_2 = root.join("checkpoint-2/layer");
        let branch_a = root.join("branch-a/upper");
        let branch_b = root.join("branch-b/upper");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&checkpoint_1).unwrap();
        std::fs::create_dir_all(&checkpoint_2).unwrap();
        std::fs::create_dir_all(&branch_a).unwrap();
        std::fs::create_dir_all(&branch_b).unwrap();
        std::fs::write(base.join("base.txt"), b"base").unwrap();
        std::fs::write(checkpoint_1.join("cp1.txt"), b"checkpoint-1").unwrap();
        std::fs::write(checkpoint_1.join("shared.txt"), b"from-cp1").unwrap();
        std::fs::write(checkpoint_2.join("cp2.txt"), b"checkpoint-2").unwrap();
        std::fs::write(checkpoint_2.join("shared.txt"), b"from-cp2").unwrap();

        let overlay_a = OverlayRootfs {
            lowerdirs: vec![checkpoint_2.clone(), checkpoint_1.clone(), base.clone()],
            upperdir: branch_a.clone(),
            workdir: root.join("branch-a/work"),
            merged: root.join("branch-a/merged"),
        };
        let overlay_b = OverlayRootfs {
            lowerdirs: vec![checkpoint_2.clone(), checkpoint_1, base],
            upperdir: branch_b.clone(),
            workdir: root.join("branch-b/work"),
            merged: root.join("branch-b/merged"),
        };
        assert!(scan_overlay_diff(&overlay_a).unwrap().is_empty());
        assert!(scan_overlay_diff(&overlay_b).unwrap().is_empty());

        std::fs::write(branch_a.join("shared.txt"), b"branch-a").unwrap();
        let a_entries = scan_overlay_diff(&overlay_a).unwrap();
        let changed = a_entries.iter().find(|e| e.path == "shared.txt").unwrap();
        assert_eq!(changed.kind, DiffKind::Modified);
        assert_eq!(changed.lower_size, Some(8));
        assert!(scan_overlay_diff(&overlay_b).unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(checkpoint_2.join("shared.txt")).unwrap(),
            "from-cp2"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn effects_report_only_changes_since_marker() {
        let (root, _paths) = temp_state("effects-since-marker");
        let lower = root.join("lower");
        let upper = root.join("upper");
        let work = root.join("work");
        let merged = root.join("merged");
        std::fs::create_dir_all(&lower).unwrap();
        std::fs::create_dir_all(&upper).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&merged).unwrap();
        std::fs::write(upper.join("before_marker"), b"old").unwrap();

        let overlay = OverlayRootfs {
            lowerdirs: vec![lower],
            upperdir: upper.clone(),
            workdir: work,
            merged,
        };
        let marked = marker_entries_from_diff(&scan_overlay_diff(&overlay).unwrap());
        std::fs::write(upper.join("after_marker"), b"new").unwrap();
        std::fs::remove_file(upper.join("before_marker")).unwrap();

        let current = marker_entries_from_diff(&scan_overlay_diff(&overlay).unwrap());
        let effects = effects_since(&marked, &current);
        let changed = effects.iter().map(|e| e.path.as_str()).collect::<Vec<_>>();
        assert_eq!(changed, vec!["after_marker", "before_marker"]);
        assert!(effects.iter().any(|e| e.path == "after_marker"
            && e.before.is_none()
            && e.after.as_deref() == Some("added")));
        assert!(effects.iter().any(|e| e.path == "before_marker"
            && e.before.as_deref() == Some("added")
            && e.after.is_none()));
        assert!(effects_json("c", "step_1", &effects)
            .get("persistent_fs_change")
            .and_then(|v| v.as_bool())
            .unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tar_writer_exports_whiteout_entries() {
        let entry = DiffEntry {
            path: "dir/deleted".to_string(),
            kind: DiffKind::Deleted,
            file_type: "whiteout".to_string(),
            size: None,
            lower_size: Some(10),
            size_delta: Some(-10),
            sensitive: false,
            fingerprint: "whiteout".to_string(),
            upper_path: None,
        };
        let mut tar = Vec::new();
        write_overlay_tar(&mut tar, &[entry]).unwrap();
        assert!(tar
            .windows(b"dir/.wh.deleted".len())
            .any(|w| w == b"dir/.wh.deleted"));
        assert_eq!(tar.len() % 512, 0);
    }

    #[test]
    fn rollout_branches_from_same_snapshot_get_independent_random_llm_steps() {
        struct RandLlmMocker {
            state: u64,
        }

        impl RandLlmMocker {
            fn new(seed: u64) -> Self {
                Self { state: seed }
            }

            fn step(&mut self) -> &'static str {
                self.state = self
                    .state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                match (self.state >> 32) % 4 {
                    0 => "edit parser",
                    1 => "add regression test",
                    2 => "tighten timeout",
                    _ => "update docs",
                }
            }
        }

        let (root, _paths) = temp_state("rollout-snapshot");
        let snapshot_upper = root.join("snapshot/upper");
        let branch_a = root.join("branch-a/upper");
        let branch_b = root.join("branch-b/upper");
        std::fs::create_dir_all(&snapshot_upper).unwrap();
        std::fs::write(snapshot_upper.join("repo.txt"), b"base-state\n").unwrap();

        clone_upperdir(&snapshot_upper, &branch_a).unwrap();
        clone_upperdir(&snapshot_upper, &branch_b).unwrap();

        let mut llm_a = RandLlmMocker::new(7);
        let mut llm_b = RandLlmMocker::new(11);
        let rollout_a = llm_a.step();
        let rollout_b = llm_b.step();
        assert_ne!(rollout_a, rollout_b);

        std::fs::write(branch_a.join("rollout.txt"), rollout_a).unwrap();
        std::fs::write(branch_b.join("rollout.txt"), rollout_b).unwrap();

        assert_eq!(
            std::fs::read_to_string(snapshot_upper.join("repo.txt")).unwrap(),
            "base-state\n"
        );
        assert!(!snapshot_upper.join("rollout.txt").exists());
        assert_eq!(
            std::fs::read_to_string(branch_a.join("repo.txt")).unwrap(),
            "base-state\n"
        );
        assert_eq!(
            std::fs::read_to_string(branch_b.join("repo.txt")).unwrap(),
            "base-state\n"
        );
        assert_ne!(
            std::fs::read_to_string(branch_a.join("rollout.txt")).unwrap(),
            std::fs::read_to_string(branch_b.join("rollout.txt")).unwrap()
        );

        std::fs::write(branch_a.join("repo.txt"), b"branch-a-state\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(branch_b.join("repo.txt")).unwrap(),
            "base-state\n"
        );
        assert_eq!(
            std::fs::read_to_string(snapshot_upper.join("repo.txt")).unwrap(),
            "base-state\n"
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
