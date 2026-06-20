//! rsrun-ext — features used only by the standalone `rsrun` CLI.
//!
//! These are kept out of `rsrun-core` so the daemon (`rsrund`) doesn't
//! pay the compile-and-load cost: rsrund operates on pre-warmed
//! namespaces under a different trust model.

pub mod cgroup;
pub mod devices;
pub mod hooks;
pub mod seccomp;

pub fn compile(
    spec: &rsrun_core::spec::Spec,
    container_id: &str,
) -> std::io::Result<rsrun_core::plan::ExtPlan> {
    let linux = spec.raw.get("linux");
    let seccomp_value = linux.and_then(|l| l.get("seccomp"));
    let resources = linux.and_then(|l| l.get("resources"));
    let hooks_value = spec.raw.get("hooks");

    let seccomp_bpf = seccomp::compile(seccomp_value)?;
    let (cgroup_v2_path, cgroup_v2_writes) = cgroup::compile(resources, container_id)?;
    // Device cgroup rules live under `linux.resources.devices`, NOT
    // `linux.devices` (which is the device *creation* list, applied via
    // mknod inside the rootfs). The eBPF program is what enforces
    // allow/deny semantics on every device access. Pass the spec's
    // `linux.devices` list too so we can implicitly allow them — the
    // child needs to mknod those before exec, which the BPF would
    // otherwise refuse under a deny-all rule.
    let extra_devices = linux.and_then(|l| l.get("devices"));
    let device_cgroup_bpf = devices::compile(resources, extra_devices)?;
    let hooks = hooks::compile(hooks_value, &spec.bundle)?;

    Ok(rsrun_core::plan::ExtPlan {
        seccomp_bpf,
        cgroup_v2_path,
        cgroup_v2_writes,
        device_cgroup_bpf,
        hooks,
    })
}
