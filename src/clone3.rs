//! Direct `clone3` wrapper.
//!
//! `nix` 0.29 has a `clone3` helper but it's marked unsafe and gated
//! behind a feature flag we'd rather avoid. Calling the syscall directly
//! is ~30 lines and lets us pass exactly the flags we want.
//!
//! Linux-only: `clone3` is a Linux syscall (number 435 on most arches).
//! On non-Linux targets the function is a stub that returns -1 so the
//! crate still compiles for IDE/cross-platform development.

use libc::c_int;

#[cfg(target_os = "linux")]
use libc::c_long;

#[cfg(target_os = "linux")]
pub const SYS_CLONE3: c_long = 435;

#[repr(C)]
#[derive(Default)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

/// Wrap `clone3`. Returns `0` in the child, the child PID in the parent,
/// or a negative errno on failure.
///
/// # Safety
/// The child returns to the caller's stack frame. Anything that would be
/// unsafe across `fork()` is unsafe here too — no allocator, no stdio
/// buffer flush, no destructors that touch shared state. Keep the child
/// path strictly syscall-only until `execve`.
#[cfg(target_os = "linux")]
pub unsafe fn clone3(args: &CloneArgs) -> c_int {
    let size = std::mem::size_of::<CloneArgs>();
    libc::syscall(SYS_CLONE3, args as *const _, size) as c_int
}

/// Non-Linux stub: clone3 doesn't exist outside Linux. Returns -1 with
/// errno=ENOSYS-equivalent so the IDE/cross-platform build links but
/// fails at runtime if anyone calls it.
#[cfg(not(target_os = "linux"))]
pub unsafe fn clone3(_args: &CloneArgs) -> c_int {
    -1
}
