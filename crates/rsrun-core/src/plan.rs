//! CompiledPlan — the runtime-ready, decision-free representation of a Spec.
//!
//! The point of compiling: the hot path (clone3 → mount → pivot_root → exec)
//! does no JSON parsing, no string searching, no decision logic. Just
//! syscalls with pre-computed args.

use crate::spec::{NamespaceKind, RLimitKind, Spec};
use nix::sched::CloneFlags;
use std::ffi::CString;
use std::path::PathBuf;

/// Per-invocation options the CLI passes to `cmd_create_full` that
/// don't belong on the spec-derived `CompiledPlan`. Defaults to
/// "no preserve_fds, use pivot_root".
#[derive(Default, Clone, Copy)]
pub struct CreateOpts {
    /// Mark fds 3..=preserve_fds+2 as non-CLOEXEC in the parent before
    /// clone3 so they inherit into the container init. 0 = none.
    pub preserve_fds: u32,
    /// Use chroot(2) instead of pivot_root(2). Engines pass this for
    /// read-only rootfs setups where pivot_root would fail.
    pub no_pivot: bool,
}

pub struct CompiledPlan {
    /// Pre-existing namespaces to join via setns(2) before clone3.
    /// These come from `linux.namespaces[].path` in the spec; the named
    /// flag is also stripped from `clone_flags` so the kernel doesn't
    /// try to create a new one.
    pub join_namespaces: Vec<(NamespaceKind, PathBuf)>,
    /// Optional payload prepared by `rsrun-ext` (seccomp, cgroups, hooks,
    /// device rules). Core treats it as opaque and applies it at the
    /// pre-defined points: parent before clone3 for cgroups, child
    /// before execve for seccomp, both ends for hooks.
    pub ext: ExtPlan,
    /// All namespace flags OR'd into one value, ready for `clone3`.
    /// In rootless mode this includes CLONE_NEWUSER.
    pub clone_flags: CloneFlags,
    /// Whether the spec requested a user namespace. The hot path checks this
    /// once; rootful mode pays a single predicted-not-taken branch.
    pub wants_userns: bool,
    /// Rootless: uid_map and gid_map line buffers, pre-formatted at compile
    /// time. Each line is "container host size\n". For rootful these are
    /// empty Vecs and never touched.
    pub uid_map_data: Vec<u8>,
    pub gid_map_data: Vec<u8>,
    /// Whether the spec set hostname (empty string is treated as unset).
    pub set_hostname: bool,
    /// Resource limits to apply via prlimit64. Compiled to (resource, soft, hard).
    pub rlimits: Vec<(libc::__rlimit_resource_t, libc::rlimit64)>,
    /// Capability bitmasks. `None` means leave inherited (no change).
    pub caps: Option<CapBitmasks>,
    pub no_new_privileges: bool,
    /// Default device nodes (mknod) to create under /dev. Pre-resolved.
    pub default_devices: Vec<DefaultDevice>,
    /// Default symlinks to create under /dev: (target, link).
    pub default_symlinks: Vec<(CString, CString)>,
    /// Masked and readonly paths.
    pub masked_paths: Vec<CString>,
    pub readonly_paths: Vec<CString>,
    pub user_uid: u32,
    pub user_gid: u32,
    pub user_additional_gids: Vec<u32>,
    pub user_umask: Option<u32>,
    /// AppArmor profile name (e.g. `docker-default`). Applied via a
    /// write to `/proc/self/attr/apparmor/exec` ("exec <profile>") so
    /// the kernel transitions on the next execve. None = unconfined.
    pub apparmor_profile: Option<CString>,
    /// SELinux exec context (e.g. `system_u:system_r:container_t:s0`).
    /// Applied via write to `/proc/self/attr/exec`. None = no transition.
    pub selinux_label: Option<CString>,
    /// `linux.sysctl` writes to apply inside the container, pre-built as
    /// (path under /proc/sys/, value bytes). Empty when no sysctls in
    /// spec — child skips the loop.
    pub sysctls: Vec<(CString, Vec<u8>)>,
    /// `linux.rootfsPropagation` flag (e.g. `MS_SHARED|MS_REC`). Zero
    /// when not specified; child skips the mount call.
    pub rootfs_propagation: nix::mount::MsFlags,
    /// `--no-pivot` engine flag. When true the child uses chroot(2)
    /// instead of pivot_root(2). Default false (rsrun's pivot_root path
    /// is the safer default; chroot is only needed for read-only
    /// rootfs setups where pivot_root would fail).
    pub no_pivot: bool,
    /// `process.oomScoreAdj` from the spec. None = leave kernel default.
    /// Written from the parent to /proc/<pid>/oom_score_adj after
    /// clone3 returns, before `start` would unblock the FIFO.
    pub oom_score_adj: Option<i32>,
    /// Hostname to set inside the UTS namespace.
    pub hostname: CString,
    /// Resolved absolute path to rootfs.
    pub root_path: PathBuf,
    pub root_readonly: bool,
    /// Mounts to perform inside the new mount namespace, in order.
    pub mounts: Vec<MountOp>,
    /// `process.terminal` from the spec. When true and a console socket
    /// path is supplied to `cmd_create`, the runtime allocates a PTY pair
    /// and sends the master fd over the socket.
    pub terminal: bool,
    /// AF_UNIX socket the engine listens on for the PTY master fd.
    /// Set by the CLI from `--console-socket`. Ignored when `terminal`
    /// is false.
    pub console_socket: Option<PathBuf>,
    /// argv as null-terminated CStrings (first is the program path).
    pub argv: Vec<CString>,
    /// envp as null-terminated CStrings.
    pub envp: Vec<CString>,
    /// Working directory inside the container.
    pub cwd: CString,
}

pub struct MountOp {
    pub source: CString,
    pub target: PathBuf,
    pub fstype: CString,
    pub flags: nix::mount::MsFlags,
    pub data: Option<CString>,
    /// Pre-formatted "0 1000 65536\n..." for `linux.mounts[].uidMappings`.
    /// Empty when this mount is not idmapped — the parent skips spawning
    /// the helper task and the child skips `mount_setattr`.
    pub idmap_uid: Vec<u8>,
    pub idmap_gid: Vec<u8>,
}

/// Pre-compiled extras supplied by `rsrun-ext`. Empty fields mean
/// "do not apply" — core skips the corresponding install steps.
#[derive(Default)]
pub struct ExtPlan {
    /// cBPF program for the OCI seccomp filter, ready for
    /// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`. Installed in
    /// the child after capabilities, before execve.
    pub seccomp_bpf: Vec<libc::sock_filter>,
    /// Absolute cgroup-v2 directory the container should join (e.g.
    /// `/sys/fs/cgroup/rsrun-<id>`). Created by ext, joined by core
    /// after clone3 by writing the child PID into `cgroup.procs`.
    pub cgroup_v2_path: Option<PathBuf>,
    /// `(filename, content)` writes into the cgroup directory, e.g.
    /// `("memory.max", b"134217728\n")`. Applied by core in the parent
    /// before clone3 (so the child enters with limits already set).
    pub cgroup_v2_writes: Vec<(String, Vec<u8>)>,
    /// device cgroup BPF program for v2 (`linux.devices` allow rules).
    /// Empty means "no per-container device filtering".
    pub device_cgroup_bpf: Vec<u8>,
    /// OCI hooks. core invokes the relevant set at each lifecycle phase.
    pub hooks: Hooks,
}

/// OCI lifecycle hooks. Each Vec is a list of commands to fork+exec at
/// the corresponding phase. The container state JSON is fed on stdin.
///
/// `prestart` and `create_runtime` fire from the parent during
/// `cmd_create` (between namespace setup and exec, OCI's pre-start
/// window). `create_container` and `start_container` fire from inside
/// the container's mount namespace, after pivot_root, before execve.
/// `poststart` fires from the parent after `cmd_start` returns;
/// `poststop` fires from the parent during `cmd_delete`.
#[derive(Default, Clone)]
pub struct Hooks {
    pub prestart: Vec<HookCmd>,
    pub create_runtime: Vec<HookCmd>,
    pub create_container: Vec<HookCmd>,
    pub start_container: Vec<HookCmd>,
    pub poststart: Vec<HookCmd>,
    pub poststop: Vec<HookCmd>,
}

#[derive(Clone)]
pub struct HookCmd {
    pub path: CString,
    pub args: Vec<CString>,
    pub env: Vec<CString>,
    pub timeout_ms: Option<u64>,
}

impl Hooks {
    /// Are all phases empty? `cmd_create` skips the persist write entirely
    /// when this is true, so containers without hooks pay nothing.
    pub fn is_empty(&self) -> bool {
        self.prestart.is_empty()
            && self.create_runtime.is_empty()
            && self.create_container.is_empty()
            && self.start_container.is_empty()
            && self.poststart.is_empty()
            && self.poststop.is_empty()
    }

    pub fn to_json(&self) -> serde_json::Value {
        fn ph(v: &[HookCmd]) -> serde_json::Value {
            serde_json::Value::Array(v.iter().map(HookCmd::to_json).collect())
        }
        serde_json::json!({
            "prestart":         ph(&self.prestart),
            "createRuntime":    ph(&self.create_runtime),
            "createContainer":  ph(&self.create_container),
            "startContainer":   ph(&self.start_container),
            "poststart":        ph(&self.poststart),
            "poststop":         ph(&self.poststop),
        })
    }

    pub fn from_json(v: &serde_json::Value) -> Self {
        let phase = |key: &str| -> Vec<HookCmd> {
            v.get(key)
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(HookCmd::from_json).collect())
                .unwrap_or_default()
        };
        Self {
            prestart: phase("prestart"),
            create_runtime: phase("createRuntime"),
            create_container: phase("createContainer"),
            start_container: phase("startContainer"),
            poststart: phase("poststart"),
            poststop: phase("poststop"),
        }
    }
}

impl HookCmd {
    fn to_json(&self) -> serde_json::Value {
        let arg_strs: Vec<String> = self
            .args
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        let env_strs: Vec<String> = self
            .env
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        serde_json::json!({
            "path": self.path.to_string_lossy(),
            "args": arg_strs,
            "env": env_strs,
            "timeout_ms": self.timeout_ms,
        })
    }

    fn from_json(v: &serde_json::Value) -> Option<Self> {
        let path = CString::new(v.get("path")?.as_str()?).ok()?;
        let to_cstrs = |key: &str| -> Vec<CString> {
            v.get(key)
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str())
                        .filter_map(|s| CString::new(s).ok())
                        .collect()
                })
                .unwrap_or_default()
        };
        let args = to_cstrs("args");
        let env = to_cstrs("env");
        let timeout_ms = v.get("timeout_ms").and_then(|t| t.as_u64());
        Some(HookCmd {
            path,
            args,
            env,
            timeout_ms,
        })
    }
}

/// Six capability sets we'll set inside the container. Each is a u64 bitmask
/// of capability indices (0..63). 64-bit covers Linux's full cap range.
#[derive(Default, Clone, Copy)]
pub struct CapBitmasks {
    pub bounding: u64,
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub ambient: u64,
}

#[derive(Clone)]
pub struct DefaultDevice {
    pub path: CString,
    pub mode: u32,  // file mode (e.g. 0o666)
    pub kind: char, // 'c' for char device
    pub major: u32,
    pub minor: u32,
}

impl CompiledPlan {
    pub fn from_spec(spec: &Spec) -> std::io::Result<Self> {
        let mut clone_flags = CloneFlags::empty();
        let mut wants_userns = false;
        let mut join_namespaces = Vec::new();
        for ns in &spec.namespaces {
            // If a path is given, the kernel namespace already exists at
            // that path (e.g. /var/run/netns/red). We setns into it after
            // clone3 instead of creating a new one. Otherwise, OR the
            // CLONE_NEW* flag in.
            if let Some(path) = ns.path.as_ref() {
                join_namespaces.push((ns.kind, path.clone()));
                continue;
            }
            match ns.kind {
                NamespaceKind::Pid => clone_flags |= CloneFlags::CLONE_NEWPID,
                NamespaceKind::Network => clone_flags |= CloneFlags::CLONE_NEWNET,
                NamespaceKind::Mount => clone_flags |= CloneFlags::CLONE_NEWNS,
                NamespaceKind::Ipc => clone_flags |= CloneFlags::CLONE_NEWIPC,
                NamespaceKind::Uts => clone_flags |= CloneFlags::CLONE_NEWUTS,
                NamespaceKind::Cgroup => clone_flags |= CloneFlags::CLONE_NEWCGROUP,
                NamespaceKind::User => {
                    wants_userns = true;
                    clone_flags |= CloneFlags::CLONE_NEWUSER;
                }
            }
        }

        // Pre-format the uid_map / gid_map line buffers at compile time so the
        // hot path just does a single write() per file. Empty when rootful.
        let uid_map_data = if wants_userns {
            format_id_map(&spec.uid_mappings)
        } else {
            Vec::new()
        };
        let gid_map_data = if wants_userns {
            format_id_map(&spec.gid_mappings)
        } else {
            Vec::new()
        };

        let mounts = spec
            .mounts
            .iter()
            .map(|m| compile_mount(m, &spec.root_path))
            .collect::<std::io::Result<Vec<_>>>()?;

        let argv = spec
            .args
            .iter()
            .map(|s| cstr(s))
            .collect::<std::io::Result<Vec<_>>>()?;
        let envp = spec
            .env
            .iter()
            .map(|s| cstr(s))
            .collect::<std::io::Result<Vec<_>>>()?;

        // Compile rlimits to (resource, rlimit64) pairs. Allocator-free hot
        // path: at apply time we just iterate and call prlimit64.
        let mut rlimit_pairs = Vec::with_capacity(spec.rlimits.len());
        for r in &spec.rlimits {
            let resource = match r.kind {
                RLimitKind::Cpu => libc::RLIMIT_CPU,
                RLimitKind::Fsize => libc::RLIMIT_FSIZE,
                RLimitKind::Data => libc::RLIMIT_DATA,
                RLimitKind::Stack => libc::RLIMIT_STACK,
                RLimitKind::Core => libc::RLIMIT_CORE,
                RLimitKind::Rss => libc::RLIMIT_RSS,
                RLimitKind::Nproc => libc::RLIMIT_NPROC,
                RLimitKind::Nofile => libc::RLIMIT_NOFILE,
                RLimitKind::Memlock => libc::RLIMIT_MEMLOCK,
                RLimitKind::As => libc::RLIMIT_AS,
                RLimitKind::Locks => libc::RLIMIT_LOCKS,
                RLimitKind::Sigpending => libc::RLIMIT_SIGPENDING,
                RLimitKind::Msgqueue => libc::RLIMIT_MSGQUEUE,
                RLimitKind::Nice => libc::RLIMIT_NICE,
                RLimitKind::Rtprio => libc::RLIMIT_RTPRIO,
                RLimitKind::Rttime => libc::RLIMIT_RTTIME,
            };
            rlimit_pairs.push((
                resource,
                libc::rlimit64 {
                    rlim_cur: r.soft,
                    rlim_max: r.hard,
                },
            ));
        }

        let caps = spec.capabilities.as_ref().map(|c| CapBitmasks {
            bounding: cap_mask(&c.bounding),
            effective: cap_mask(&c.effective),
            permitted: cap_mask(&c.permitted),
            inheritable: cap_mask(&c.inheritable),
            ambient: cap_mask(&c.ambient),
        });

        let default_devices = vec![
            DefaultDevice {
                path: cstr("/dev/null")?,
                mode: 0o666,
                kind: 'c',
                major: 1,
                minor: 3,
            },
            DefaultDevice {
                path: cstr("/dev/zero")?,
                mode: 0o666,
                kind: 'c',
                major: 1,
                minor: 5,
            },
            DefaultDevice {
                path: cstr("/dev/full")?,
                mode: 0o666,
                kind: 'c',
                major: 1,
                minor: 7,
            },
            DefaultDevice {
                path: cstr("/dev/random")?,
                mode: 0o666,
                kind: 'c',
                major: 1,
                minor: 8,
            },
            DefaultDevice {
                path: cstr("/dev/urandom")?,
                mode: 0o666,
                kind: 'c',
                major: 1,
                minor: 9,
            },
            DefaultDevice {
                path: cstr("/dev/tty")?,
                mode: 0o666,
                kind: 'c',
                major: 5,
                minor: 0,
            },
        ];
        let default_symlinks = vec![
            (cstr("/proc/self/fd")?, cstr("/dev/fd")?),
            (cstr("/proc/self/fd/0")?, cstr("/dev/stdin")?),
            (cstr("/proc/self/fd/1")?, cstr("/dev/stdout")?),
            (cstr("/proc/self/fd/2")?, cstr("/dev/stderr")?),
            (cstr("pts/ptmx")?, cstr("/dev/ptmx")?),
        ];

        let masked_paths = spec
            .masked_paths
            .iter()
            .map(|s| cstr(s))
            .collect::<std::io::Result<Vec<_>>>()?;
        let readonly_paths = spec
            .readonly_paths
            .iter()
            .map(|s| cstr(s))
            .collect::<std::io::Result<Vec<_>>>()?;

        Ok(Self {
            join_namespaces,
            ext: ExtPlan::default(),
            terminal: spec.terminal,
            console_socket: None,
            clone_flags,
            wants_userns,
            uid_map_data,
            gid_map_data,
            hostname: cstr(&spec.hostname)?,
            set_hostname: !spec.hostname.is_empty(),
            root_path: spec.root_path.clone(),
            root_readonly: spec.root_readonly,
            mounts,
            argv,
            envp,
            cwd: cstr(&spec.cwd)?,
            rlimits: rlimit_pairs,
            caps,
            no_new_privileges: spec.no_new_privileges,
            default_devices,
            default_symlinks,
            masked_paths,
            readonly_paths,
            user_uid: spec.user_uid,
            user_gid: spec.user_gid,
            user_additional_gids: spec.user_additional_gids.clone(),
            user_umask: spec.user_umask,
            apparmor_profile: spec.apparmor_profile.as_deref().map(cstr).transpose()?,
            selinux_label: spec.selinux_label.as_deref().map(cstr).transpose()?,
            sysctls: spec
                .sysctls
                .iter()
                .map(|(k, v)| {
                    let path = format!("/proc/sys/{}", k.replace('.', "/"));
                    Ok((cstr(&path)?, v.as_bytes().to_vec()))
                })
                .collect::<std::io::Result<Vec<_>>>()?,
            rootfs_propagation: parse_propagation(spec.rootfs_propagation.as_deref()),
            no_pivot: false,
            oom_score_adj: spec.oom_score_adj,
        })
    }
}

/// Parse OCI rootfsPropagation strings into `MsFlags`. Returns the
/// MsFlags::empty() when the option is None or unrecognized — the
/// child then skips the mount() call entirely.
fn parse_propagation(s: Option<&str>) -> nix::mount::MsFlags {
    use nix::mount::MsFlags;
    match s.unwrap_or("") {
        "shared" => MsFlags::MS_SHARED,
        "slave" => MsFlags::MS_SLAVE,
        "private" => MsFlags::MS_PRIVATE,
        "unbindable" => MsFlags::MS_UNBINDABLE,
        "rshared" => MsFlags::MS_SHARED | MsFlags::MS_REC,
        "rslave" => MsFlags::MS_SLAVE | MsFlags::MS_REC,
        "rprivate" => MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        "runbindable" => MsFlags::MS_UNBINDABLE | MsFlags::MS_REC,
        _ => MsFlags::empty(),
    }
}

/// Convert a list of OCI cap names (e.g. "CAP_NET_RAW") to a bitmask.
fn cap_mask(names: &[String]) -> u64 {
    let mut mask = 0u64;
    for n in names {
        if let Some(bit) = cap_bit(n) {
            mask |= 1u64 << bit;
        }
    }
    mask
}

/// Public re-export of `cap_bit` for `runtime::cmd_exec` to parse
/// `process.json` capabilities without re-implementing the table.
pub fn cap_bit_for_name(name: &str) -> Option<u32> {
    cap_bit(name)
}

/// Linux cap bit numbers per <linux/capability.h>.
fn cap_bit(name: &str) -> Option<u32> {
    let s = name.strip_prefix("CAP_").unwrap_or(name);
    Some(match s {
        "CHOWN" => 0,
        "DAC_OVERRIDE" => 1,
        "DAC_READ_SEARCH" => 2,
        "FOWNER" => 3,
        "FSETID" => 4,
        "KILL" => 5,
        "SETGID" => 6,
        "SETUID" => 7,
        "SETPCAP" => 8,
        "LINUX_IMMUTABLE" => 9,
        "NET_BIND_SERVICE" => 10,
        "NET_BROADCAST" => 11,
        "NET_ADMIN" => 12,
        "NET_RAW" => 13,
        "IPC_LOCK" => 14,
        "IPC_OWNER" => 15,
        "SYS_MODULE" => 16,
        "SYS_RAWIO" => 17,
        "SYS_CHROOT" => 18,
        "SYS_PTRACE" => 19,
        "SYS_PACCT" => 20,
        "SYS_ADMIN" => 21,
        "SYS_BOOT" => 22,
        "SYS_NICE" => 23,
        "SYS_RESOURCE" => 24,
        "SYS_TIME" => 25,
        "SYS_TTY_CONFIG" => 26,
        "MKNOD" => 27,
        "LEASE" => 28,
        "AUDIT_WRITE" => 29,
        "AUDIT_CONTROL" => 30,
        "SETFCAP" => 31,
        "MAC_OVERRIDE" => 32,
        "MAC_ADMIN" => 33,
        "SYSLOG" => 34,
        "WAKE_ALARM" => 35,
        "BLOCK_SUSPEND" => 36,
        "AUDIT_READ" => 37,
        "PERFMON" => 38,
        "BPF" => 39,
        "CHECKPOINT_RESTORE" => 40,
        _ => return None,
    })
}

/// Format an OCI uidMappings/gidMappings array into the kernel's
/// /proc/<pid>/uid_map line format: "container host size\n" per line.
fn format_id_map(mappings: &[crate::spec::IdMapping]) -> Vec<u8> {
    let mut out = Vec::with_capacity(mappings.len() * 32);
    for m in mappings {
        use std::io::Write as _;
        let _ = writeln!(out, "{} {} {}", m.container_id, m.host_id, m.size);
    }
    out
}

fn compile_mount(m: &crate::spec::MountSpec, root: &std::path::Path) -> std::io::Result<MountOp> {
    use nix::mount::MsFlags;
    let mut flags = MsFlags::empty();
    let mut data_parts = Vec::new();
    for opt in &m.options {
        match opt.as_str() {
            "ro" => flags |= MsFlags::MS_RDONLY,
            "rw" => {} // default
            "nosuid" => flags |= MsFlags::MS_NOSUID,
            "nodev" => flags |= MsFlags::MS_NODEV,
            "noexec" => flags |= MsFlags::MS_NOEXEC,
            "relatime" => flags |= MsFlags::MS_RELATIME,
            "noatime" => flags |= MsFlags::MS_NOATIME,
            "strictatime" => flags |= MsFlags::MS_STRICTATIME,
            "bind" => flags |= MsFlags::MS_BIND,
            "rbind" => flags |= MsFlags::MS_BIND | MsFlags::MS_REC,
            "private" => flags |= MsFlags::MS_PRIVATE,
            "rprivate" => flags |= MsFlags::MS_PRIVATE | MsFlags::MS_REC,
            "shared" => flags |= MsFlags::MS_SHARED,
            "rshared" => flags |= MsFlags::MS_SHARED | MsFlags::MS_REC,
            "slave" => flags |= MsFlags::MS_SLAVE,
            "rslave" => flags |= MsFlags::MS_SLAVE | MsFlags::MS_REC,
            other => data_parts.push(other.to_string()),
        }
    }
    let data = if data_parts.is_empty() {
        None
    } else {
        Some(cstr(&data_parts.join(","))?)
    };

    // Destination is interpreted relative to the new rootfs, but at mount
    // time we're still in the host mount-ns and pivot_root hasn't happened.
    // We mount at <rootfs>/<destination> and pivot_root will see the right
    // tree.
    let dst_rel = m.destination.trim_start_matches('/');
    let target = root.join(dst_rel);

    Ok(MountOp {
        source: cstr(&m.source)?,
        target,
        fstype: cstr(&m.fstype)?,
        flags,
        data,
        idmap_uid: format_id_map(&m.uid_mappings),
        idmap_gid: format_id_map(&m.gid_mappings),
    })
}

fn cstr(s: &str) -> std::io::Result<CString> {
    CString::new(s).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "string contains NUL byte")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::Spec;
    use serde_json::json;
    use std::path::Path;

    fn parse(v: serde_json::Value) -> Spec {
        Spec::from_value(v, Path::new("/bundle")).unwrap()
    }

    fn minimal_spec() -> serde_json::Value {
        json!({
            "process": {"args": ["/bin/true"]},
            "root": {"path": "rootfs"}
        })
    }

    #[test]
    fn cap_bit_table_covers_known_names() {
        // Spot-check a few cap bits by their kernel-defined values.
        assert_eq!(cap_bit("CAP_CHOWN"), Some(0));
        assert_eq!(cap_bit("CAP_DAC_OVERRIDE"), Some(1));
        assert_eq!(cap_bit("CAP_NET_BIND_SERVICE"), Some(10));
        assert_eq!(cap_bit("CAP_SYS_ADMIN"), Some(21));
        // Strip-prefix variant works.
        assert_eq!(cap_bit("CHOWN"), Some(0));
        assert_eq!(cap_bit("CAP_NOT_REAL"), None);
    }

    #[test]
    fn cap_mask_or_combines_bits() {
        let mask = cap_mask(&["CAP_CHOWN".into(), "CAP_NET_BIND_SERVICE".into()]);
        assert_eq!(mask, (1u64 << 0) | (1u64 << 10));
    }

    #[test]
    fn namespaces_split_into_clone_flags_and_join_paths() {
        let v = json!({
            "process": {"args": ["/bin/true"]},
            "root": {"path": "rootfs"},
            "linux": {
                "namespaces": [
                    {"type": "pid"},
                    {"type": "mount"},
                    {"type": "network", "path": "/var/run/netns/red"}
                ]
            }
        });
        let plan = CompiledPlan::from_spec(&parse(v)).unwrap();
        // pid + mount go into clone_flags; network has a path so it's
        // joined later via setns and not in the clone3 flags.
        assert!(plan
            .clone_flags
            .contains(nix::sched::CloneFlags::CLONE_NEWPID));
        assert!(plan
            .clone_flags
            .contains(nix::sched::CloneFlags::CLONE_NEWNS));
        assert!(!plan
            .clone_flags
            .contains(nix::sched::CloneFlags::CLONE_NEWNET));
        assert_eq!(plan.join_namespaces.len(), 1);
        assert_eq!(
            plan.join_namespaces[0].0,
            crate::spec::NamespaceKind::Network
        );
        assert_eq!(
            plan.join_namespaces[0].1.as_path(),
            Path::new("/var/run/netns/red")
        );
    }

    #[test]
    fn user_namespace_sets_wants_userns() {
        let mut v = minimal_spec();
        v["linux"] = json!({"namespaces": [{"type": "user"}]});
        let plan = CompiledPlan::from_spec(&parse(v)).unwrap();
        assert!(plan.wants_userns);
        assert!(plan
            .clone_flags
            .contains(nix::sched::CloneFlags::CLONE_NEWUSER));
    }

    #[test]
    fn rootful_skips_uid_map_buffers() {
        let plan = CompiledPlan::from_spec(&parse(minimal_spec())).unwrap();
        assert!(!plan.wants_userns);
        assert!(plan.uid_map_data.is_empty());
        assert!(plan.gid_map_data.is_empty());
    }

    #[test]
    fn rootless_pre_formats_id_map_lines() {
        let v = json!({
            "process": {"args": ["/bin/true"]},
            "root": {"path": "rootfs"},
            "linux": {
                "namespaces": [{"type": "user"}],
                "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
                "gidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}]
            }
        });
        let plan = CompiledPlan::from_spec(&parse(v)).unwrap();
        assert_eq!(plan.uid_map_data, b"0 1000 1\n");
        assert_eq!(plan.gid_map_data, b"0 1000 1\n");
    }

    #[test]
    fn empty_hostname_disables_sethostname() {
        let mut v = minimal_spec();
        v["hostname"] = json!("");
        let plan = CompiledPlan::from_spec(&parse(v)).unwrap();
        assert!(!plan.set_hostname);
    }

    #[test]
    fn nonempty_hostname_enables_sethostname() {
        let mut v = minimal_spec();
        v["hostname"] = json!("mybox");
        let plan = CompiledPlan::from_spec(&parse(v)).unwrap();
        assert!(plan.set_hostname);
        assert_eq!(plan.hostname.to_str().unwrap(), "mybox");
    }

    #[test]
    fn ext_plan_default_is_empty() {
        let plan = CompiledPlan::from_spec(&parse(minimal_spec())).unwrap();
        assert!(plan.ext.seccomp_bpf.is_empty());
        assert!(plan.ext.cgroup_v2_path.is_none());
        assert!(plan.ext.cgroup_v2_writes.is_empty());
        assert!(plan.ext.hooks.is_empty());
    }

    #[test]
    fn hooks_to_from_json_roundtrip() {
        let hooks = Hooks {
            prestart: vec![HookCmd {
                path: CString::new("/usr/bin/true").unwrap(),
                args: vec![CString::new("true").unwrap()],
                env: vec![CString::new("FOO=bar").unwrap()],
                timeout_ms: Some(5000),
            }],
            ..Default::default()
        };
        let v = hooks.to_json();
        let restored = Hooks::from_json(&v);
        assert_eq!(restored.prestart.len(), 1);
        assert_eq!(restored.prestart[0].path.to_str().unwrap(), "/usr/bin/true");
        assert_eq!(restored.prestart[0].args.len(), 1);
        assert_eq!(restored.prestart[0].args[0].to_str().unwrap(), "true");
        assert_eq!(restored.prestart[0].env[0].to_str().unwrap(), "FOO=bar");
        assert_eq!(restored.prestart[0].timeout_ms, Some(5000));
    }

    #[test]
    fn hooks_is_empty_correctly() {
        let empty = Hooks::default();
        assert!(empty.is_empty());

        let with_one = Hooks {
            poststop: vec![HookCmd {
                path: CString::new("/x").unwrap(),
                args: vec![],
                env: vec![],
                timeout_ms: None,
            }],
            ..Default::default()
        };
        assert!(!with_one.is_empty());
    }
}
