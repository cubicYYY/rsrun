//! Runtime entry point. The real implementation lives in `runtime_linux`
//! (Linux-only — uses clone3, namespaces, pivot_root, capset, prlimit64,
//! etc., all of which are Linux kernel features without portable
//! equivalents). For non-Linux targets we provide stubs that compile
//! cleanly but error at runtime, so the crate stays useful for
//! IDE/cross-platform editing.

#[cfg(target_os = "linux")]
#[path = "runtime_linux.rs"]
mod imp;

#[cfg(not(target_os = "linux"))]
#[path = "runtime_stub.rs"]
mod imp;

pub use imp::{cmd_create, cmd_delete, cmd_exec, cmd_kill, cmd_list, cmd_start, cmd_state};
