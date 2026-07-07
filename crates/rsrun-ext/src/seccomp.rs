//! Seccomp profile compiler.
//!
//! Reads `linux.seccomp` from the OCI spec and produces a cBPF program
//! the runtime installs in the child via
//! `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`.
//!
//! Implementation: a small name-level cBPF emitter. OCI argument
//! conditions are intentionally ignored for now, but per-syscall actions
//! and errno values are preserved.

use serde_json::Value;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// Compile a seccomp profile (the `linux.seccomp` object from
/// `config.json`) into a cBPF program. Returns an empty Vec if the
/// spec has no seccomp section.
pub fn compile(seccomp: Option<&Value>) -> std::io::Result<Vec<libc::sock_filter>> {
    let Some(seccomp) = seccomp else {
        return Ok(Vec::new());
    };

    let arch = host_audit_arch()?;
    let default = parse_action(
        seccomp.get("defaultAction").and_then(Value::as_str),
        seccomp
            .get("defaultErrnoRet")
            .and_then(Value::as_i64)
            .map(|n| n as u32),
    )?;

    let mut rules = Vec::new();
    if let Some(arr) = seccomp.get("syscalls").and_then(Value::as_array) {
        for entry in arr {
            let action = parse_action(
                entry.get("action").and_then(Value::as_str),
                entry
                    .get("errnoRet")
                    .and_then(Value::as_i64)
                    .map(|n| n as u32),
            )?;
            // OCI seccomp also has `args` for argument matching; this emitter
            // ignores it for now. The important Docker compatibility detail is
            // preserving non-ALLOW actions such as clone3 -> ENOSYS.
            let names = entry
                .get("names")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            for name in names {
                if let Some(nr) = syscall_nr(name) {
                    rules.push((nr as u32, action));
                }
            }
        }
    }

    if rules.is_empty() && default == SECCOMP_RET_ALLOW {
        return Ok(Vec::new());
    }

    Ok(emit_filter(arch, &rules, default))
}

fn parse_action(s: Option<&str>, errno_ret: Option<u32>) -> std::io::Result<u32> {
    match s.unwrap_or("SCMP_ACT_ERRNO") {
        "SCMP_ACT_ALLOW" => Ok(SECCOMP_RET_ALLOW),
        "SCMP_ACT_ERRNO" => Ok(SECCOMP_RET_ERRNO | errno_ret.unwrap_or(libc::EPERM as u32)),
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => Ok(SECCOMP_RET_KILL_THREAD),
        "SCMP_ACT_KILL_PROCESS" => Ok(SECCOMP_RET_KILL_PROCESS),
        "SCMP_ACT_LOG" => Ok(SECCOMP_RET_LOG),
        "SCMP_ACT_TRAP" => Ok(SECCOMP_RET_TRAP),
        other => Err(std::io::Error::other(format!(
            "unsupported seccomp action: {other}"
        ))),
    }
}

fn host_audit_arch() -> std::io::Result<u32> {
    if cfg!(target_arch = "x86_64") {
        Ok(0xc000_003e)
    } else if cfg!(target_arch = "aarch64") {
        Ok(0xc000_00b7)
    } else {
        Err(std::io::Error::other("seccomp: unsupported target arch"))
    }
}

/// Resolve a syscall name to its number on the given target. We rely on
/// libc's syscall constants, which exist on the build host's arch.
/// Cross-arch profile compilation isn't supported in v0.
fn syscall_nr(name: &str) -> Option<i64> {
    syscall_nr_native(name)
}

fn emit_filter(arch: u32, rules: &[(u32, u32)], default: u32) -> Vec<libc::sock_filter> {
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    let mut prog = Vec::with_capacity(5 + rules.len() * 2);
    // struct seccomp_data: nr at offset 0, arch at offset 4.
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, 4));
    prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0));
    prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, 0));
    for (nr, action) in rules {
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *nr, 0, 1));
        prog.push(stmt(BPF_RET | BPF_K, *action));
    }
    prog.push(stmt(BPF_RET | BPF_K, default));
    prog
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
            assert!(
                parse_action(Some(action), None).is_ok(),
                "action {action} rejected"
            );
        }
    }

    #[test]
    fn errno_action_preserves_errno_ret() {
        assert_eq!(
            parse_action(Some("SCMP_ACT_ERRNO"), Some(38)).unwrap(),
            SECCOMP_RET_ERRNO | 38
        );
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn known_syscall_names_resolve_on_aarch64() {
        // Spot-check common runtime-loader calls on arm64.
        assert_eq!(syscall_nr_aarch64("read"), Some(63));
        assert_eq!(syscall_nr_aarch64("write"), Some(64));
        assert_eq!(syscall_nr_aarch64("execve"), Some(221));
        assert_eq!(syscall_nr_aarch64("openat"), Some(56));
        assert_eq!(syscall_nr_aarch64("fcntl"), Some(25));
        assert_eq!(syscall_nr_aarch64("mmap"), Some(222));
        assert_eq!(syscall_nr_aarch64("newfstatat"), Some(79));
        assert_eq!(syscall_nr_aarch64("fstat"), Some(80));
        assert_eq!(syscall_nr_aarch64("fadvise64"), Some(223));
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
        // The emitter produces: arch check, syscall-nr load, one
        // compare+return pair per syscall, and default return.
        assert!(prog.len() >= 4);
        assert!(prog.iter().any(|ins| ins.k == SECCOMP_RET_ALLOW));
        assert!(prog
            .iter()
            .any(|ins| ins.k == (SECCOMP_RET_ERRNO | libc::EPERM as u32)));
    }

    #[test]
    fn per_syscall_errno_action_is_emitted() {
        let v = json!({
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 1,
            "syscalls": [
                {
                    "names": ["read"],
                    "action": "SCMP_ACT_ALLOW"
                },
                {
                    "names": ["clone3"],
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 38
                }
            ]
        });
        let prog = compile(Some(&v)).unwrap();
        assert!(prog.iter().any(|ins| ins.k == SECCOMP_RET_ALLOW));
        assert!(prog.iter().any(|ins| ins.k == (SECCOMP_RET_ERRNO | 38)));
        assert!(prog.iter().any(|ins| ins.k == (SECCOMP_RET_ERRNO | 1)));
    }

    #[test]
    fn empty_deny_profile_still_emits_filter() {
        let v = json!({
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 13,
            "syscalls": []
        });
        let prog = compile(Some(&v)).unwrap();
        assert!(!prog.is_empty());
        assert_eq!(prog.last().unwrap().k, SECCOMP_RET_ERRNO | 13);
    }
}
