//! Device cgroup eBPF — `linux.resources.devices` allow/deny rules.
//!
//! cgroup-v2 device control is enforced by a `BPF_PROG_TYPE_CGROUP_DEVICE`
//! eBPF program attached to the container's cgroup directory. The kernel
//! invokes the program on every device access (open / mknod) and the
//! program returns 1 (allow) or 0 (deny).
//!
//! This module emits the program and load+attach plumbing directly via
//! `syscall(__NR_bpf, ...)`. No libbpf, no aya, no rbpf — same approach
//! crun uses, ~200 LOC, zero new crate dependencies.
//!
//! Layout we generate (default-deny epilogue):
//!
//! ```text
//! prologue:           # 6 insns
//!   R2 = ctx->access_type
//!   R3 = ctx->access_type    # second copy for shift
//!   R4 = ctx->major
//!   R5 = ctx->minor
//!   R3 >>= 16                # R3 = type bit (1=block, 2=char)
//!   R2 &= 0xffff             # R2 = access bits (1=mknod, 2=read, 4=write)
//!
//! per rule (worst case 5 insns; wildcards drop their check entirely):
//!   if R3 != type, skip      # one BPF_JNE — omitted on type='a'
//!   if (R2 & ~rule_access),  # one BPF_JSET — omitted on access='rwm' / 0
//!      skip
//!   if R4 != major, skip     # omitted on major=-1
//!   if R5 != minor, skip     # omitted on minor=-1
//!   R0 = allow ? 1 : 0; EXIT
//!
//! epilogue:           # 2 insns
//!   R0 = 0; EXIT     (default-deny)
//! ```
//!
//! Output is `Vec<u8>` of raw `bpf_insn`s — `runtime` calls
//! `attach_device_program(cgroup_path, &bytes)` after creating the
//! cgroup directory, before `clone3`. The hot create path pays nothing
//! when the spec has no device rules.

use serde_json::Value;

// ---- bpf_insn wire format -------------------------------------------------

/// Raw eBPF instruction, exactly the kernel ABI.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfInsn {
    code: u8,
    /// dst_reg in low nibble, src_reg in high nibble.
    regs: u8,
    off: i16,
    imm: i32,
}

const fn regs(dst: u8, src: u8) -> u8 {
    (src << 4) | (dst & 0x0f)
}

// ---- opcode bits (subset we need; see <linux/bpf.h>) ----------------------

const BPF_LDX: u8 = 0x01;
const BPF_W: u8 = 0x00;
const BPF_MEM: u8 = 0x60;
const BPF_ALU: u8 = 0x04;
const BPF_ALU64: u8 = 0x07;
const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;
const BPF_AND: u8 = 0x50;
const BPF_RSH: u8 = 0x70;
const BPF_MOV: u8 = 0xb0;
const BPF_JMP: u8 = 0x05;
const BPF_JNE: u8 = 0x50;
const BPF_JSET: u8 = 0x40;
const BPF_EXIT_OP: u8 = 0x90;

const fn ldx_w(dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn {
        code: BPF_LDX | BPF_W | BPF_MEM,
        regs: regs(dst, src),
        off,
        imm: 0,
    }
}

const fn alu32_imm(op: u8, dst: u8, imm: i32) -> BpfInsn {
    BpfInsn {
        code: BPF_ALU | op | BPF_K,
        regs: regs(dst, 0),
        off: 0,
        imm,
    }
}

const fn alu64_mov_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn {
        code: BPF_ALU64 | BPF_MOV | BPF_K,
        regs: regs(dst, 0),
        off: 0,
        imm,
    }
}

const fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> BpfInsn {
    BpfInsn {
        code: BPF_JMP | op | BPF_K,
        regs: regs(dst, 0),
        off,
        imm,
    }
}

const EXIT_INSN: BpfInsn = BpfInsn {
    code: BPF_JMP | BPF_EXIT_OP,
    regs: 0,
    off: 0,
    imm: 0,
};

// silence "unused" on BPF_X — kept for future extensions (register-form
// instructions). Removing it doesn't affect emitted code.
const _: u8 = BPF_X;

// ---- compiled rule --------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct DeviceRule {
    /// Kernel BPF_DEVCG_DEV_*: 1 = block, 2 = char, 0 = wildcard.
    kind: u8,
    /// Bitmask of BPF_DEVCG_ACC_*: 1 = mknod, 2 = read, 4 = write.
    /// 0 OR 0x7 means "any access" — the JSET check is skipped.
    access: u32,
    /// -1 = wildcard major.
    major: i32,
    /// -1 = wildcard minor.
    minor: i32,
    allow: bool,
}

// ---- public API -----------------------------------------------------------

/// Compile `linux.resources.devices` into a raw eBPF program.
/// Returns an empty Vec when the spec has no rules — the runtime then
/// skips load+attach entirely (the hot path sees one branch).
///
/// `extra_devices` is the spec's `linux.devices` list (the *creation*
/// list — what the child mknods inside the rootfs). The OCI runtime
/// spec says these devices must be accessible to the workload, so they
/// are implicitly allowed regardless of the user's resources.devices
/// rules. We synthesize an allow rule for each and prepend it to the
/// rule list so first-match-wins lets the mknods succeed.
///
/// Plus the six OCI default devices (/dev/null, /dev/zero, /dev/full,
/// /dev/random, /dev/urandom, /dev/tty) are also implicitly allowed —
/// runc/crun behave the same. Without this an OCI bundle with the
/// generator's default `[{Allow: false, Access: "rwm"}]` rule would
/// fail because rsrun couldn't even create the default /dev nodes.
pub fn compile(
    resources: Option<&Value>,
    extra_devices: Option<&Value>,
) -> std::io::Result<Vec<u8>> {
    let user_rules = parse_rules(resources);
    if user_rules.is_empty() {
        return Ok(Vec::new());
    }

    let mut rules: Vec<DeviceRule> = Vec::with_capacity(user_rules.len() + 12);
    rules.extend(default_oci_devices());
    rules.extend(parse_extra_devices(extra_devices));
    rules.extend(user_rules);

    Ok(emit_program(&rules))
}

/// The six OCI-mandated default devices, all char devices, all rwm.
/// Pre-built at compile time; the function is just `&'static [...]`-ish.
fn default_oci_devices() -> impl Iterator<Item = DeviceRule> {
    const DEFAULTS: &[(i32, i32)] = &[
        (1, 3), // /dev/null
        (1, 5), // /dev/zero
        (1, 7), // /dev/full
        (1, 8), // /dev/random
        (1, 9), // /dev/urandom
        (5, 0), // /dev/tty
    ];
    DEFAULTS.iter().map(|&(maj, min)| DeviceRule {
        kind: 2, // CHAR
        access: 0x7,
        major: maj,
        minor: min,
        allow: true,
    })
}

/// `linux.devices` lists devices the runtime should mknod inside the
/// rootfs. They must be accessible from the workload, so each becomes
/// an implicit allow rule. Type 'p' (FIFO) and 'u' (unbuffered char)
/// don't have direct cgroup-device counterparts; we map 'u' to char
/// (BPF_DEVCG_DEV_CHAR) and skip 'p' entirely.
fn parse_extra_devices(extra: Option<&Value>) -> Vec<DeviceRule> {
    let arr = match extra.and_then(Value::as_array) {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(arr.len());
    for d in arr {
        let kind = match d.get("type").and_then(Value::as_str).unwrap_or("") {
            "b" => 1,
            "c" | "u" => 2,
            _ => continue,
        };
        let major = d.get("major").and_then(Value::as_i64).map(|n| n as i32);
        let minor = d.get("minor").and_then(Value::as_i64).map(|n| n as i32);
        if major.is_none() || minor.is_none() {
            continue;
        }
        out.push(DeviceRule {
            kind,
            access: 0x7,
            major: major.unwrap(),
            minor: minor.unwrap(),
            allow: true,
        });
    }
    out
}

fn parse_rules(resources: Option<&Value>) -> Vec<DeviceRule> {
    let arr = match resources
        .and_then(|r| r.get("devices"))
        .and_then(Value::as_array)
    {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(arr.len());
    for r in arr {
        let allow = r.get("allow").and_then(Value::as_bool).unwrap_or(false);
        let kind = match r.get("type").and_then(Value::as_str).unwrap_or("a") {
            "a" => 0,
            "b" => 1, // BPF_DEVCG_DEV_BLOCK
            "c" => 2, // BPF_DEVCG_DEV_CHAR
            "u" => 2, // unbuffered char treated as char (legacy)
            _ => 0,
        };
        let access_str = r.get("access").and_then(Value::as_str).unwrap_or("rwm");
        let mut access: u32 = 0;
        for ch in access_str.chars() {
            match ch {
                'm' => access |= 1,
                'r' => access |= 2,
                'w' => access |= 4,
                _ => {}
            }
        }
        let major = r
            .get("major")
            .and_then(Value::as_i64)
            .map(|n| n as i32)
            .unwrap_or(-1);
        let minor = r
            .get("minor")
            .and_then(Value::as_i64)
            .map(|n| n as i32)
            .unwrap_or(-1);
        out.push(DeviceRule {
            kind,
            access,
            major,
            minor,
            allow,
        });
    }
    out
}

// ---- emitter --------------------------------------------------------------

fn emit_program(rules: &[DeviceRule]) -> Vec<u8> {
    // Capacity: prologue (6) + at most 5 insns per rule + epilogue (2).
    // Over-allocating by ~10% is cheaper than re-growing.
    let mut p: Vec<BpfInsn> = Vec::with_capacity(8 + rules.len() * 5);

    // Prologue: extract type/access/major/minor into R2..R5.
    // ctx->access_type is encoded as (access << 16) | type, so:
    //   R2 = access_type & 0xffff      → device type (1=block, 2=char)
    //   R3 = access_type >> 16         → access bits (1=mknod, 2=read, 4=write)
    // Two LDX is cheaper than one LDX + a register copy; the JIT folds.
    p.push(ldx_w(3, 1, 0)); // R3 = ctx->access_type
    p.push(ldx_w(2, 1, 0)); // R2 = ctx->access_type
    p.push(ldx_w(4, 1, 4)); // R4 = ctx->major
    p.push(ldx_w(5, 1, 8)); // R5 = ctx->minor
    p.push(alu32_imm(BPF_RSH, 3, 16)); // R3 >>= 16  → access bits
    p.push(alu32_imm(BPF_AND, 2, 0xffff)); // R2 &= 0xffff → device type

    // First-match-wins: once a wildcard rule (type='a' AND no access/
    // major/minor restriction) is emitted it always matches, so any
    // later rules are dead code. The verifier rejects unreachable
    // insns, so we stop emitting at that point. crun does the same
    // (HAS_WILDCARD flag in libcrun/ebpf.c). Also skips the default
    // epilogue when a wildcard was emitted, since the wildcard's EXIT
    // is already an unconditional terminator.
    let mut wildcard_emitted = false;
    for r in rules {
        emit_rule(&mut p, r);
        if is_wildcard(r) {
            wildcard_emitted = true;
            break;
        }
    }

    if !wildcard_emitted {
        // Default-deny epilogue. Reached only when no wildcard rule
        // matched any earlier specific rule.
        p.push(alu64_mov_imm(0, 0));
        p.push(EXIT_INSN);
    }

    insns_to_bytes(&p)
}

fn is_wildcard(r: &DeviceRule) -> bool {
    r.kind == 0 && (r.access == 0 || r.access == 0x7) && r.major < 0 && r.minor < 0
}

fn emit_rule(p: &mut Vec<BpfInsn>, r: &DeviceRule) {
    // Indices of conditional jumps whose `off` we'll patch once we know
    // the rule's tail position. Stack-allocated fixed-size; max 4 jumps.
    let mut jumps = [0u32; 4];
    let mut nj = 0usize;

    // Type check on R2 (now holds device type post-prologue).
    if r.kind != 0 {
        jumps[nj] = p.len() as u32;
        nj += 1;
        p.push(jmp_imm(BPF_JNE, 2, r.kind as i32, 0));
    }

    // Access check on R3 (now holds access bits): skip the rule if the
    // request has any access bits *not* in rule.access. One BPF_JSET on
    // (R3 & ~rule.access). Wildcard access ('rwm' = 0x7) skips entirely.
    if r.access != 0 && r.access != 0x7 {
        let mask = (!r.access) & 0x7;
        if mask != 0 {
            jumps[nj] = p.len() as u32;
            nj += 1;
            p.push(jmp_imm(BPF_JSET, 3, mask as i32, 0));
        }
    }

    if r.major >= 0 {
        jumps[nj] = p.len() as u32;
        nj += 1;
        p.push(jmp_imm(BPF_JNE, 4, r.major, 0));
    }
    if r.minor >= 0 {
        jumps[nj] = p.len() as u32;
        nj += 1;
        p.push(jmp_imm(BPF_JNE, 5, r.minor, 0));
    }

    p.push(alu64_mov_imm(0, if r.allow { 1 } else { 0 }));
    p.push(EXIT_INSN);

    // Patch jumps to land just past the EXIT (next rule's start).
    let after = p.len();
    for &j in &jumps[..nj] {
        let off = (after as i32) - (j as i32) - 1;
        p[j as usize].off = off as i16;
    }
}

fn insns_to_bytes(p: &[BpfInsn]) -> Vec<u8> {
    // BpfInsn is #[repr(C)] and exactly 8 bytes. memcpy-style copy.
    let n = std::mem::size_of_val(p);
    let mut out = Vec::with_capacity(n);
    // SAFETY: BpfInsn is Plain Old Data with no padding (8 bytes total),
    // and Vec<u8>::set_len after a memcpy of n bytes is safe.
    unsafe {
        std::ptr::copy_nonoverlapping(p.as_ptr() as *const u8, out.as_mut_ptr(), n);
        out.set_len(n);
    }
    out
}

// Syscall glue (BPF_PROG_LOAD + BPF_PROG_ATTACH) lives in `rsrun-core`'s
// `runtime::attach_device_cgroup_bpf` so the daemon path can call it
// without depending on rsrun-ext.

// ---- tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_rules_produce_empty_program() {
        assert!(compile(None, None).unwrap().is_empty());
        assert!(compile(Some(&json!({})), None).unwrap().is_empty());
        assert!(compile(Some(&json!({"devices": []})), None).unwrap().is_empty());
    }

    #[test]
    fn deny_all_program_includes_oci_defaults() {
        // {allow:false, type:a} preceded by 6 implicit OCI default
        // device allows. Each default rule: type(1) + major(1) +
        // minor(1) + mov(1) + exit(1) = 5 insns. Then the wildcard
        // deny: mov(1) + exit(1) = 2.  Prologue 6 + 6×5 + 2 = 38
        // insns = 304 bytes. No epilogue (wildcard short-circuits).
        let v = json!({"devices": [{"allow": false, "type": "a"}]});
        let bytes = compile(Some(&v), None).unwrap();
        assert_eq!(bytes.len(), 38 * 8);
    }

    #[test]
    fn allow_one_chrdev_then_wildcard_deny() {
        // 6 default OCI device rules (5 insns each) + user allow (5)
        // + wildcard deny (2). Prologue 6 + 30 + 5 + 2 = 43 insns.
        let v = json!({
            "devices": [
                {"allow": true, "type": "c", "major": 1, "minor": 5, "access": "rwm"},
                {"allow": false, "type": "a"}
            ]
        });
        let bytes = compile(Some(&v), None).unwrap();
        assert_eq!(bytes.len(), 43 * 8);
    }

    #[test]
    fn access_subset_emits_jset() {
        // 6 default OCI rules (5 each = 30) + user rule with type+jset
        // (4 insns) + default-deny epilogue (2). Prologue 6 + 30 + 4 + 2 = 42.
        let v = json!({
            "devices": [{"allow": true, "type": "c", "access": "r"}]
        });
        let bytes = compile(Some(&v), None).unwrap();
        assert_eq!(bytes.len(), 42 * 8);
    }

    #[test]
    fn wildcard_short_circuits_emission() {
        // 6 default OCI rules (30) + wildcard allow (2). Prologue 6 +
        // 30 + 2 = 38. No epilogue (wildcard short-circuits).
        let v = json!({
            "devices": [{"allow": true, "type": "a", "access": "rwm"}]
        });
        let bytes = compile(Some(&v), None).unwrap();
        assert_eq!(bytes.len(), 38 * 8);
    }

    #[test]
    fn parse_handles_partial_fields() {
        // Missing major/minor → wildcards. Missing access → "rwm".
        let v = json!({"devices": [{"allow": true, "type": "c"}]});
        let rules = parse_rules(Some(&v));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].kind, 2);
        assert_eq!(rules[0].access, 0x7);
        assert_eq!(rules[0].major, -1);
        assert_eq!(rules[0].minor, -1);
        assert!(rules[0].allow);
    }
}
