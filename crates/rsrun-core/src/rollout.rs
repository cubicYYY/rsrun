//! Rollout-oriented runtime extensions.
//!
//! This module is the public boundary for filesystem state primitives
//! and direct step execution. The OCI lifecycle remains exported from
//! the crate root.

pub use crate::runtime::{
    cmd_changed_files, cmd_checkpoint, cmd_diff, cmd_effects, cmd_exec_rollout, cmd_export_diff,
    cmd_fork, cmd_fork_checkpoint, cmd_mark, cmd_reset, cmd_restore, cmd_snapshot, RolloutExecOpts,
};
