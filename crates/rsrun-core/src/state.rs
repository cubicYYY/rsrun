//! Per-container state under /run/rsrun/<id>/.
//!
//! Layout:
//!   /run/rsrun/<id>/state.json   — minimal OCI-shaped state for compatibility
//!   /run/rsrun/<id>/init.fifo    — created by `create`, opened-blocking by init,
//!                                  unblocked when `start` writes to it
//!   /run/rsrun/<id>/init.pid     — PID of the cloned init process (host PID)

use serde_json::json;
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
        if self.root.exists() {
            std::fs::remove_dir_all(&self.root)?;
        }
        Ok(())
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
    let state = json!({
        "ociVersion": "1.0.2",
        "id": id,
        "status": status,
        "pid": pid,
        "bundle": bundle.to_string_lossy(),
        "annotations": {},
        // Internal hint used by `state` to detect pid reuse. Not part of OCI.
        "commHint": comm_hint,
    });
    std::fs::write(paths.state_file(), serde_json::to_vec(&state)?)
}

pub fn read_pid(paths: &ContainerPaths) -> std::io::Result<i32> {
    let s = std::fs::read_to_string(paths.pid_file())?;
    s.trim().parse().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad pid file: {e}"))
    })
}
