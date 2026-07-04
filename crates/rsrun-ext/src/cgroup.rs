//! cgroup-v2 limits.
//!
//! Reads `linux.resources` from the OCI spec and produces the file
//! writes needed under `/sys/fs/cgroup/<id>`. Core creates the
//! directory before clone3, applies the writes, then places the child
//! with `cgroup.procs` by default or `CLONE_INTO_CGROUP` when explicitly
//! enabled.
//!
//! v2-only. v1 is end-of-life on systemd-cgroup hosts and not in scope.

use serde_json::Value;
use std::path::PathBuf;

const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

pub fn compile(
    resources: Option<&Value>,
    container_id: &str,
) -> std::io::Result<(Option<PathBuf>, Vec<(String, Vec<u8>)>)> {
    let Some(resources) = resources else {
        return Ok((None, Vec::new()));
    };

    // Skip the cgroup work entirely if the host is cgroup-v1.
    if !is_cgroup_v2() {
        return Ok((None, Vec::new()));
    }

    let writes = compile_writes(resources);

    // The cgroup directory is needed if EITHER (a) we have knob writes
    // (memory.max etc.) OR (b) we have device rules to attach a BPF
    // program to. We can't tell from here whether device rules exist
    // (`devices::compile` runs separately), but we can check the spec.
    let has_devices = resources
        .get("devices")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    if writes.is_empty() && !has_devices {
        return Ok((None, Vec::new()));
    }
    let dir = PathBuf::from(format!("{CGROUP_V2_ROOT}/rsrun-{container_id}"));
    Ok((Some(dir), writes))
}

/// Spec-resources → cgroup-v2 file writes. Host-independent, so it
/// runs the same on macOS dev hosts as on Linux. The caller adds the
/// directory path and the cgroup-v2 availability check.
pub(crate) fn compile_writes(resources: &Value) -> Vec<(String, Vec<u8>)> {
    let mut writes: Vec<(String, Vec<u8>)> = Vec::new();

    // memory.{max, swap.max, low}
    if let Some(memory) = resources.get("memory") {
        if let Some(limit) = memory.get("limit").and_then(Value::as_i64) {
            writes.push(("memory.max".to_string(), encode_bytes(limit)));
        }
        if let Some(swap) = memory.get("swap").and_then(Value::as_i64) {
            // OCI's `swap` is total memory+swap; cgroup-v2 wants swap-only.
            // If memory.limit is also set, subtract.
            let mem = memory.get("limit").and_then(Value::as_i64).unwrap_or(0);
            let swap_only = if mem > 0 && swap >= mem {
                swap - mem
            } else {
                swap
            };
            writes.push(("memory.swap.max".to_string(), encode_bytes(swap_only)));
        }
        if let Some(reserve) = memory.get("reservation").and_then(Value::as_i64) {
            writes.push(("memory.low".to_string(), encode_bytes(reserve)));
        }
    }

    // cpu.{max, weight}
    if let Some(cpu) = resources.get("cpu") {
        let quota = cpu.get("quota").and_then(Value::as_i64);
        let period = cpu.get("period").and_then(Value::as_u64);
        if quota.is_some() || period.is_some() {
            // cpu.max format: "<quota> <period>" or "max <period>".
            let q = quota.map(|v| v.to_string()).unwrap_or_else(|| "max".into());
            let p = period.unwrap_or(100_000);
            writes.push(("cpu.max".to_string(), format!("{q} {p}").into_bytes()));
        }
        // OCI shares are 2..262144; cgroup-v2 weight is 1..10000. The
        // standard conversion is: weight = 1 + (shares - 2) * 9999 / 262142.
        if let Some(shares) = cpu.get("shares").and_then(Value::as_u64) {
            let weight = 1 + (shares.saturating_sub(2) * 9999) / 262_142;
            let weight = weight.clamp(1, 10_000);
            writes.push(("cpu.weight".to_string(), weight.to_string().into_bytes()));
        }
        if let Some(cpus) = cpu.get("cpus").and_then(Value::as_str) {
            writes.push(("cpuset.cpus".to_string(), cpus.as_bytes().to_vec()));
        }
        if let Some(mems) = cpu.get("mems").and_then(Value::as_str) {
            writes.push(("cpuset.mems".to_string(), mems.as_bytes().to_vec()));
        }
    }

    // pids.max
    if let Some(pids) = resources.get("pids") {
        if let Some(limit) = pids.get("limit").and_then(Value::as_i64) {
            writes.push(("pids.max".to_string(), encode_pids(limit)));
        }
    }

    // io.max — block-IO bandwidth. OCI's blockIO is more elaborate;
    // v0 honors only the per-device `throttleReadBpsDevice` /
    // `throttleWriteBpsDevice` arrays, which are the common cases.
    if let Some(blockio) = resources.get("blockIO") {
        compile_blockio(blockio, &mut writes);
    }

    writes
}

fn compile_blockio(blockio: &Value, out: &mut Vec<(String, Vec<u8>)>) {
    let mut entries: Vec<(String, String, u64)> = Vec::new();
    for (key, knob) in [
        ("throttleReadBpsDevice", "rbps"),
        ("throttleWriteBpsDevice", "wbps"),
        ("throttleReadIOPSDevice", "riops"),
        ("throttleWriteIOPSDevice", "wiops"),
    ] {
        if let Some(arr) = blockio.get(key).and_then(Value::as_array) {
            for d in arr {
                let major = d.get("major").and_then(Value::as_u64);
                let minor = d.get("minor").and_then(Value::as_u64);
                let rate = d.get("rate").and_then(Value::as_u64);
                if let (Some(maj), Some(min), Some(r)) = (major, minor, rate) {
                    entries.push((format!("{maj}:{min}"), knob.to_string(), r));
                }
            }
        }
    }
    // io.max wants one line per device with all four knobs in a single
    // write. Group by device.
    use std::collections::BTreeMap;
    let mut by_dev: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for (dev, knob, rate) in entries {
        by_dev.entry(dev).or_default().insert(knob, rate);
    }
    for (dev, knobs) in by_dev {
        let mut line = dev;
        for (knob, rate) in knobs {
            line.push_str(&format!(" {knob}={rate}"));
        }
        line.push('\n');
        out.push(("io.max".to_string(), line.into_bytes()));
    }
}

fn encode_bytes(v: i64) -> Vec<u8> {
    if v <= 0 {
        b"max".to_vec()
    } else {
        v.to_string().into_bytes()
    }
}

fn encode_pids(v: i64) -> Vec<u8> {
    if v <= 0 {
        b"max".to_vec()
    } else {
        v.to_string().into_bytes()
    }
}

fn is_cgroup_v2() -> bool {
    std::fs::metadata("/sys/fs/cgroup/cgroup.controllers").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn find<'a>(writes: &'a [(String, Vec<u8>)], key: &str) -> Option<&'a [u8]> {
        writes.iter().find(|(k, _)| k == key).map(|(_, v)| &v[..])
    }

    #[test]
    fn memory_max_and_low() {
        let r = json!({
            "memory": {"limit": 134217728, "reservation": 67108864}
        });
        let w = compile_writes(&r);
        assert_eq!(find(&w, "memory.max"), Some(&b"134217728"[..]));
        assert_eq!(find(&w, "memory.low"), Some(&b"67108864"[..]));
    }

    #[test]
    fn memory_swap_subtracts_memory_limit() {
        // OCI swap=200 means total memory+swap=200; with mem=128, swap-only=72.
        let r = json!({"memory": {"limit": 128, "swap": 200}});
        let w = compile_writes(&r);
        assert_eq!(find(&w, "memory.swap.max"), Some(&b"72"[..]));
    }

    #[test]
    fn unlimited_memory_renders_as_max() {
        let r = json!({"memory": {"limit": 0}});
        let w = compile_writes(&r);
        assert_eq!(find(&w, "memory.max"), Some(&b"max"[..]));
    }

    #[test]
    fn cpu_quota_and_period() {
        let r = json!({"cpu": {"quota": 50000, "period": 100000}});
        let w = compile_writes(&r);
        assert_eq!(find(&w, "cpu.max"), Some(&b"50000 100000"[..]));
    }

    #[test]
    fn cpu_period_only_uses_max_quota() {
        let r = json!({"cpu": {"period": 50000}});
        let w = compile_writes(&r);
        assert_eq!(find(&w, "cpu.max"), Some(&b"max 50000"[..]));
    }

    #[test]
    fn cpu_shares_to_weight_clamps_to_v2_range() {
        // OCI shares 2 → weight 1 (low end).
        let r = json!({"cpu": {"shares": 2}});
        let w = compile_writes(&r);
        assert_eq!(find(&w, "cpu.weight"), Some(&b"1"[..]));

        // OCI shares 1024 (default) maps to ~40 in cgroup-v2 weight.
        let r = json!({"cpu": {"shares": 1024}});
        let w = compile_writes(&r);
        let weight: u64 = std::str::from_utf8(find(&w, "cpu.weight").unwrap())
            .unwrap()
            .parse()
            .unwrap();
        assert!((30..=50).contains(&weight), "weight={weight}");

        // Very large shares should clamp to 10000.
        let r = json!({"cpu": {"shares": 1_000_000}});
        let w = compile_writes(&r);
        // At shares=262144 we'd hit exactly 10000; above that, clamp.
        let weight: u64 = std::str::from_utf8(find(&w, "cpu.weight").unwrap())
            .unwrap()
            .parse()
            .unwrap();
        assert!(weight <= 10_000);
    }

    #[test]
    fn cpuset_cpus_and_mems_passthrough() {
        let r = json!({"cpu": {"cpus": "0-3", "mems": "0"}});
        let w = compile_writes(&r);
        assert_eq!(find(&w, "cpuset.cpus"), Some(&b"0-3"[..]));
        assert_eq!(find(&w, "cpuset.mems"), Some(&b"0"[..]));
    }

    #[test]
    fn pids_max_and_unlimited() {
        let r = json!({"pids": {"limit": 100}});
        let w = compile_writes(&r);
        assert_eq!(find(&w, "pids.max"), Some(&b"100"[..]));

        let r = json!({"pids": {"limit": 0}});
        let w = compile_writes(&r);
        assert_eq!(find(&w, "pids.max"), Some(&b"max"[..]));
    }

    #[test]
    fn blockio_groups_per_device_into_one_line() {
        let r = json!({
            "blockIO": {
                "throttleReadBpsDevice":  [{"major": 8, "minor": 0, "rate": 1048576}],
                "throttleWriteBpsDevice": [{"major": 8, "minor": 0, "rate": 524288}]
            }
        });
        let w = compile_writes(&r);
        let line = find(&w, "io.max").unwrap();
        let s = std::str::from_utf8(line).unwrap();
        assert!(s.starts_with("8:0 "));
        assert!(s.contains("rbps=1048576"));
        assert!(s.contains("wbps=524288"));
        assert!(s.ends_with("\n"));
    }

    #[test]
    fn empty_resources_produces_nothing() {
        let r = json!({});
        let w = compile_writes(&r);
        assert!(w.is_empty());
    }
}
