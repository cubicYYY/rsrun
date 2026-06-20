//! Device cgroup rules.
//!
//! `linux.devices` is a list of `{type, major, minor, fileMode, uid, gid}`
//! entries describing devices to create *inside* the container, plus a
//! sibling `linux.resources.devices` list with allow/deny rules for the
//! device cgroup BPF program.
//!
//! v0 status: the device-creation half is implemented in core's child
//! path (via the existing default-devices machinery; `linux.devices`
//! entries are layered on top). The BPF allow/deny program is **not yet
//! attached** — rsrun relies on the default-deny-everything-except-the-
//! six-default-chrdevs posture from cgroup-v2's controller, which covers
//! the common case but does not honor custom allow rules. Tracked in
//! docs/roadmap.md.

use serde_json::Value;

/// Parse `linux.devices` and emit a placeholder. Currently returns an
/// empty Vec so core skips BPF attach. Device *creation* (mknod) is
/// handled in core by the `linux.devices` field on the spec; here we
/// only handle the cgroup-allow side.
pub fn compile(_devices: Option<&Value>) -> std::io::Result<Vec<u8>> {
    // TODO: emit a BPF_PROG_TYPE_CGROUP_DEVICE program from the
    // `linux.resources.devices` rules. For v0 the default cgroup-v2
    // device controller posture is what's enforced.
    Ok(Vec::new())
}
