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
    let devices_value = linux.and_then(|l| l.get("devices"));
    let hooks_value = spec.raw.get("hooks");

    let seccomp_bpf = seccomp::compile(seccomp_value)?;
    let (cgroup_v2_path, cgroup_v2_writes) = cgroup::compile(resources, container_id)?;
    let device_cgroup_bpf = devices::compile(devices_value)?;
    let hooks = hooks::compile(hooks_value, &spec.bundle)?;

    Ok(rsrun_core::plan::ExtPlan {
        seccomp_bpf,
        cgroup_v2_path,
        cgroup_v2_writes,
        device_cgroup_bpf,
        hooks,
    })
}
