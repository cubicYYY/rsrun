//! Non-Linux stubs.
//!
//! rsrun is fundamentally Linux-only — every container primitive
//! (namespaces, cgroups, capabilities, mounts) is a Linux kernel
//! feature. This module exists so the crate compiles for IDE/editor
//! support on macOS and other non-Linux platforms. Each stub returns
//! a clear error if anyone actually invokes it.

use std::path::Path;

fn unsupported() -> std::io::Error {
    std::io::Error::other(
        "rsrun is Linux-only — namespaces, cgroups, capabilities, and pivot_root \
         are Linux kernel features. Build and run on Linux.",
    )
}

pub fn cmd_create(
    _id: &str,
    _bundle: &Path,
    _pid_file: Option<&Path>,
) -> std::io::Result<()> {
    Err(unsupported())
}

pub fn cmd_start(_id: &str) -> std::io::Result<()> {
    Err(unsupported())
}

pub fn cmd_delete(_id: &str, _force: bool) -> std::io::Result<()> {
    Err(unsupported())
}

pub fn cmd_state(_id: &str) -> std::io::Result<()> {
    Err(unsupported())
}

pub fn cmd_kill(_id: &str, _signal: &str) -> std::io::Result<()> {
    Err(unsupported())
}

pub fn cmd_exec(
    _id: &str,
    _process_json: &Path,
    _pid_file: Option<&Path>,
    _detach: bool,
) -> std::io::Result<()> {
    Err(unsupported())
}

pub fn cmd_list() -> std::io::Result<()> {
    Err(unsupported())
}

