//! rsrun-ext — features used only by the standalone `rsrun` CLI.
//!
//! These are kept out of `rsrun-core` so the daemon (`rsrund`) doesn't
//! pay the compile-and-load cost: rsrund operates on pre-warmed
//! namespaces under a different trust model.
//!
//! Each capability is a Cargo feature, all enabled by default. Users
//! who want a minimal binary can build with `--no-default-features`
//! and pick only what they need.

#[cfg(feature = "cgroup-limits")]
pub mod cgroup;
#[cfg(feature = "device-cgroup-bpf")]
pub mod devices;
#[cfg(feature = "hooks")]
pub mod hooks;
#[cfg(feature = "seccomp")]
pub mod seccomp;

pub fn compile(
    spec: &rsrun_core::spec::Spec,
    container_id: &str,
) -> std::io::Result<rsrun_core::plan::ExtPlan> {
    let linux = spec.raw.get("linux");
    #[cfg(any(
        feature = "seccomp",
        feature = "cgroup-limits",
        feature = "device-cgroup-bpf",
        feature = "hooks",
    ))]
    let _ = linux;

    #[cfg(feature = "seccomp")]
    let seccomp_bpf = seccomp::compile(linux.and_then(|l| l.get("seccomp")))?;
    #[cfg(not(feature = "seccomp"))]
    let seccomp_bpf = Vec::new();

    #[cfg(feature = "cgroup-limits")]
    let (cgroup_v2_path, cgroup_v2_writes) =
        cgroup::compile(linux.and_then(|l| l.get("resources")), container_id)?;
    #[cfg(not(feature = "cgroup-limits"))]
    let (cgroup_v2_path, cgroup_v2_writes) = {
        let _ = container_id;
        (None, Vec::new())
    };

    // Device cgroup rules live under `linux.resources.devices`, NOT
    // `linux.devices` (which is the device *creation* list, applied via
    // mknod inside the rootfs). The eBPF program is what enforces
    // allow/deny semantics on every device access. Pass the spec's
    // `linux.devices` list too so we can implicitly allow them — the
    // child needs to mknod those before exec, which the BPF would
    // otherwise refuse under a deny-all rule.
    #[cfg(feature = "device-cgroup-bpf")]
    let device_cgroup_bpf = devices::compile(
        linux.and_then(|l| l.get("resources")),
        linux.and_then(|l| l.get("devices")),
    )?;
    #[cfg(not(feature = "device-cgroup-bpf"))]
    let device_cgroup_bpf: Vec<u8> = Vec::new();

    #[cfg(feature = "hooks")]
    let hooks = hooks::compile(spec.raw.get("hooks"), &spec.bundle)?;
    #[cfg(not(feature = "hooks"))]
    let hooks = rsrun_core::plan::Hooks::default();

    Ok(rsrun_core::plan::ExtPlan {
        seccomp_bpf,
        cgroup_v2_path,
        cgroup_v2_writes,
        device_cgroup_bpf,
        hooks,
    })
}
