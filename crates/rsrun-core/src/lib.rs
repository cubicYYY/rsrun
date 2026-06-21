//! rsrun-core — hot-path OCI lifecycle.
//!
//! What's here: spec parser, `CompiledPlan`, the `clone3` wrapper, and
//! the syscall sequence that becomes the running container. Both the
//! `rsrun` CLI and the `rsrund` daemon depend on this crate.
//!
//! What's *not* here: seccomp, cgroup limits, hooks, TTY allocation,
//! AppArmor / SELinux. Those live in `rsrun-ext` and are linked only
//! into the standalone `rsrun` binary.

pub mod clone3;
pub mod plan;
pub mod spec;
pub mod state;

mod runtime;

pub use runtime::{
    cmd_create, cmd_create_full, cmd_create_with_ext, cmd_delete, cmd_exec, cmd_exec_full,
    cmd_kill, cmd_list, cmd_start, cmd_state,
};

#[cfg(feature = "update")]
pub use runtime::cmd_update;
#[cfg(feature = "stats")]
pub use runtime::{cmd_events, cmd_stats};
#[cfg(feature = "pause")]
pub use runtime::{cmd_pause, cmd_resume};
