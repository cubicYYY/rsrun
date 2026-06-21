//! Seccomp profile compiler.
//!
//! Reads `linux.seccomp` from the OCI spec and produces a cBPF program
//! the runtime installs in the child via
//! `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`.
//!
//! Implementation: [`seccompiler`] from AWS Firecracker. Profiled
//! against `libseccomp` and a hand-rolled BPF emitter on the OCI
//! default profile (462 syscalls); see `docs/benchmarks.md`.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch,
};
use serde_json::Value;
use std::collections::BTreeMap;

/// Compile a seccomp profile (the `linux.seccomp` object from
/// `config.json`) into a cBPF program. Returns an empty Vec if the
/// spec has no seccomp section.
pub fn compile(seccomp: Option<&Value>) -> std::io::Result<Vec<libc::sock_filter>> {
    let Some(seccomp) = seccomp else {
        return Ok(Vec::new());
    };

    let arch = host_target_arch()?;
    let default = parse_action(seccomp.get("defaultAction").and_then(Value::as_str))?;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    if let Some(arr) = seccomp.get("syscalls").and_then(Value::as_array) {
        for entry in arr {
            let action = parse_action(entry.get("action").and_then(Value::as_str))?;
            // OCI seccomp also has `args` for argument matching; v0 ignores
            // it. The default profile only uses argument matching for a
            // handful of edge cases (namespace-create flag filtering).
            let names = entry
                .get("names")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            for name in names {
                if let Some(nr) = syscall_nr(name, arch) {
                    rules.entry(nr).or_default();
                    // We model "syscall is in this list with this action"
                    // by placing one allow-rule for that syscall_nr; the
                    // mismatch_action below kicks in for others.
                    let _ = action;
                }
            }
        }
    }

    if rules.is_empty() {
        return Ok(Vec::new());
    }

    // seccompiler v0.5 builds a filter with: rules (per-syscall),
    // mismatch_action (when no syscall matches), match_action (when a
    // rule matches but its constraints fail). For OCI's name-only
    // semantics we want: match → action-of-the-entry (we use Allow
    // because rsrun only honors allowlist entries today),
    // mismatch → defaultAction.
    let filter = SeccompFilter::new(
        rules,
        default,
        SeccompAction::Allow,
        arch,
    )
    .map_err(io_err)?;
    let prog: BpfProgram = filter.try_into().map_err(io_err)?;

    // BpfProgram is Vec<sock_filter> in seccompiler's wire shape; both
    // map 1:1 to libc::sock_filter via #[repr(C)].
    let bytes: Vec<libc::sock_filter> = unsafe {
        let len = prog.len();
        let cap = prog.capacity();
        let ptr = prog.as_ptr() as *mut libc::sock_filter;
        std::mem::forget(prog);
        Vec::from_raw_parts(ptr, len, cap)
    };
    Ok(bytes)
}

fn parse_action(s: Option<&str>) -> std::io::Result<SeccompAction> {
    match s.unwrap_or("SCMP_ACT_ERRNO") {
        "SCMP_ACT_ALLOW" => Ok(SeccompAction::Allow),
        "SCMP_ACT_ERRNO" => Ok(SeccompAction::Errno(libc::EPERM as u32)),
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => Ok(SeccompAction::KillThread),
        "SCMP_ACT_KILL_PROCESS" => Ok(SeccompAction::KillProcess),
        "SCMP_ACT_LOG" => Ok(SeccompAction::Log),
        "SCMP_ACT_TRAP" => Ok(SeccompAction::Trap),
        other => Err(std::io::Error::other(format!(
            "unsupported seccomp action: {other}"
        ))),
    }
}

fn host_target_arch() -> std::io::Result<TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Ok(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(TargetArch::aarch64)
    } else {
        Err(std::io::Error::other("seccomp: unsupported target arch"))
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(format!("seccomp: {e}"))
}

/// Resolve a syscall name to its number on the given target. We rely on
/// libc's syscall constants, which exist on the build host's arch.
/// Cross-arch profile compilation isn't supported in v0.
fn syscall_nr(name: &str, arch: TargetArch) -> Option<i64> {
    if !arch_matches_host(arch) {
        return None;
    }
    syscall_nr_native(name)
}

fn arch_matches_host(arch: TargetArch) -> bool {
    match arch {
        TargetArch::x86_64 => cfg!(target_arch = "x86_64"),
        TargetArch::aarch64 => cfg!(target_arch = "aarch64"),
        _ => false,
    }
}

#[cfg(target_arch = "aarch64")]
fn syscall_nr_native(name: &str) -> Option<i64> {
    syscall_nr_aarch64(name)
}

#[cfg(target_arch = "x86_64")]
fn syscall_nr_native(name: &str) -> Option<i64> {
    syscall_nr_x86_64(name)
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn syscall_nr_native(_name: &str) -> Option<i64> {
    None
}

#[cfg(target_arch = "aarch64")]
include!("syscall_table_aarch64.rs");

#[cfg(target_arch = "x86_64")]
include!("syscall_table_x86_64.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn none_profile_returns_empty() {
        let prog = compile(None).unwrap();
        assert!(prog.is_empty());
    }

    #[test]
    fn empty_syscalls_array_returns_empty() {
        let v = json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []});
        let prog = compile(Some(&v)).unwrap();
        assert!(prog.is_empty());
    }

    #[test]
    fn unknown_action_errors() {
        let v = json!({
            "defaultAction": "SCMP_ACT_NEW_NOT_REAL",
            "syscalls": []
        });
        assert!(compile(Some(&v)).is_err());
    }

    #[test]
    fn valid_actions_all_accepted() {
        for action in [
            "SCMP_ACT_ALLOW",
            "SCMP_ACT_ERRNO",
            "SCMP_ACT_KILL",
            "SCMP_ACT_KILL_THREAD",
            "SCMP_ACT_KILL_PROCESS",
            "SCMP_ACT_LOG",
            "SCMP_ACT_TRAP",
        ] {
            assert!(parse_action(Some(action)).is_ok(), "action {action} rejected");
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn known_syscall_names_resolve_on_aarch64() {
        // Spot-check: read(63), write(64), execve(221), openat(56).
        assert_eq!(syscall_nr_aarch64("read"), Some(63));
        assert_eq!(syscall_nr_aarch64("write"), Some(64));
        assert_eq!(syscall_nr_aarch64("execve"), Some(221));
        assert_eq!(syscall_nr_aarch64("openat"), Some(56));
        assert_eq!(syscall_nr_aarch64("not_a_real_syscall"), None);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn known_syscall_names_resolve_on_x86_64() {
        // Spot-check: read(0), write(1), execve(59), openat(257).
        assert_eq!(syscall_nr_x86_64("read"), Some(0));
        assert_eq!(syscall_nr_x86_64("write"), Some(1));
        assert_eq!(syscall_nr_x86_64("execve"), Some(59));
        assert_eq!(syscall_nr_x86_64("openat"), Some(257));
        assert_eq!(syscall_nr_x86_64("clone3"), Some(435));
        assert_eq!(syscall_nr_x86_64("not_a_real_syscall"), None);
    }

    #[test]
    fn small_allowlist_compiles_to_nontrivial_program() {
        let v = json!({
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names": ["read", "write", "exit", "exit_group"],
                    "action": "SCMP_ACT_ALLOW"
                }
            ]
        });
        let prog = compile(Some(&v)).unwrap();
        // seccompiler emits at minimum: arch check (a few instrs) +
        // syscall-nr check per allowed syscall + ret allow + ret default.
        // This now exercises the x86_64 table too — previously, an empty
        // table on x86_64 silently produced a no-op filter (compile()
        // returned an empty Vec in `if rules.is_empty()`).
        assert!(prog.len() >= 4);
    }
}
