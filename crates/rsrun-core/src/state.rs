//! Per-container state under /run/rsrun/<id>/.
//!
//! Layout:
//!   /run/rsrun/<id>/state.json   — minimal OCI-shaped state for compatibility
//!   /run/rsrun/<id>/init.fifo    — created by `create`, opened-blocking by init,
//!                                  unblocked when `start` writes to it
//!   /run/rsrun/<id>/init.pid     — PID of the cloned init process (host PID)

use std::path::{Path, PathBuf};

pub struct ContainerPaths {
    pub root: PathBuf,
}

impl ContainerPaths {
    pub fn for_id(id: &str) -> Self {
        // Honor RSRUN_ROOT override (set via --root flag). Default: /run/rsrun
        // for root callers, $XDG_RUNTIME_DIR/rsrun (or /tmp/rsrun-<uid>) for
        // unprivileged callers.
        let root_dir = std::env::var_os("RSRUN_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                // Auto-pick based on uid.
                if unsafe { libc::geteuid() } == 0 {
                    PathBuf::from("/run/rsrun")
                } else if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
                    PathBuf::from(xdg).join("rsrun")
                } else {
                    PathBuf::from(format!("/tmp/rsrun-{}", unsafe { libc::geteuid() }))
                }
            });
        Self {
            root: root_dir.join(id),
        }
    }

    pub fn fifo(&self) -> PathBuf {
        self.root.join("init.fifo")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.root.join("init.pid")
    }

    pub fn state_file(&self) -> PathBuf {
        self.root.join("state.json")
    }

    pub fn ensure(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root)
    }

    pub fn destroy(&self) -> std::io::Result<()> {
        match std::fs::remove_dir_all(&self.root) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub fn write_state(
    paths: &ContainerPaths,
    id: &str,
    pid: i32,
    bundle: &Path,
    status: &str,
    comm_hint: Option<&str>,
) -> std::io::Result<()> {
    let bundle = bundle.to_string_lossy();
    let mut out = Vec::with_capacity(
        96 + id.len() + status.len() + bundle.len() + comm_hint.map(str::len).unwrap_or(4),
    );
    out.extend_from_slice(b"{\"ociVersion\":\"1.0.2\",\"id\":");
    serde_json::to_writer(&mut out, id)?;
    out.extend_from_slice(b",\"status\":");
    serde_json::to_writer(&mut out, status)?;
    out.extend_from_slice(b",\"pid\":");
    out.extend_from_slice(pid.to_string().as_bytes());
    out.extend_from_slice(b",\"bundle\":");
    serde_json::to_writer(&mut out, bundle.as_ref())?;
    out.extend_from_slice(b",\"annotations\":{},\"commHint\":");
    match comm_hint {
        Some(comm) => serde_json::to_writer(&mut out, comm)?,
        None => out.extend_from_slice(b"null"),
    }
    out.push(b'}');
    std::fs::write(paths.state_file(), out)
}

pub fn read_pid(paths: &ContainerPaths) -> std::io::Result<i32> {
    let s = std::fs::read_to_string(paths.pid_file())?;
    s.trim().parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad pid file: {e}"),
        )
    })
}
