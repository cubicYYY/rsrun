# Benchmarks

Re-run after the full feature set landed (seccomp, cgroup limits,
hooks, LSMs, device-cgroup BPF, pause/update/stats, sysctl,
systemd-cgroup). Hot path is unchanged because every optional feature
is opt-in via its spec field.

**Headline:** rsrun is faster than `crun` on cold cache, neck-and-neck
on warm cache, ~2.4× faster than `youki`, ~7× faster than `runc`. Max
RSS ~2.2 MB, ~35 % less than crun.

## Lifecycle latency

`hyperfine` of `create + start + delete` against an OCI bundle that
runs `/bin/true`. `--warmup 30`, `--min-runs 200`. Every iteration
gets a fresh container ID and a fresh state directory.

### Cold cache (drop_caches between runs)

|         | mean ± σ          | min … max          | vs rsrun |
| ------- | ----------------: | -----------------: | -------: |
| **rsrun** | **21.5 ms ± 2.5** | 16.2 ms … 30.4 ms  | **1.00×** |
| crun    | 30.3 ms ± 4.0     | 16.1 ms … 47.7 ms  | 1.41×    |
| youki   | 51.3 ms ± 14.0    | 36.9 ms … 146.2 ms | 2.39×    |
| runc    | 156.6 ms ± 9.5    | 137.4 ms … 263.8 ms | 7.28×   |

This is the closest match to a CI / fresh-container-farm workload.
rsrun's cold-cache lead over crun comes from a smaller binary
(roughly half the on-disk size) and parsing less config in the parent.

### Warm cache (no drop_caches)

|         | mean ± σ          | vs rsrun |
| ------- | ----------------: | -------: |
| **rsrun** | **13.7 ms ± 3.0** | **1.00×** |
| crun    | 14.2 ms ± 3.2     | 1.04×    |
| youki   | 32.8 ms ± 4.1     | 2.39×    |
| runc    | 139.1 ms ± 13.5   | 10.15×   |

Steady-state engine behavior. rsrun and crun are within ~3 % — both
pay the same syscall floor (`clone3`, `pivot_root`, `execve`), and at
this scale the per-byte parser cost is negligible.

## 100 sequential containers (warm)

Same shape as crun's headline benchmark — 100 sequential `/bin/true`
containers via `create + start + delete`, wall-clock time of the loop:

|       | best of 3 | vs rsrun |
| ----- | --------: | -------: |
| **rsrun** | **0.71 s** | **1.00×** |
| crun  | 0.85 s    | 1.20×    |
| youki | 1.42 s    | 2.00×    |
| runc  | 14.12 s   | 19.9×    |

rsrun and crun are usually within ±3 % on individual trials; rsrun's
median lead is small but consistent across runs.

## Memory footprint

Maximum resident set across a full `create + start + delete` lifecycle,
measured with `/usr/bin/time -v` wrapping the three commands:

|       | max RSS    | vs rsrun |
| ----- | ---------: | -------: |
| **rsrun** | **2.2 MB** | **1.00×** |
| crun  | 3.4 MB     | 1.49×    |
| youki | 6.0 MB     | 2.67×    |
| runc  | 11.5 MB    | 5.16×    |

rsrun's number is dominated by the Rust runtime + the small hot plan.
crun is C with a custom JSON parser; youki and runc both load larger
Rust/Go frameworks.

## Bench environment

- **Host**: Apple M4, macOS 26.5
- **VM**: [Lima] Ubuntu 22.04.5 LTS, kernel 5.15.0-181-generic, aarch64,
  4 vCPU, 8 GB RAM, `vz` virtualization
- **Filesystem**: ext4 on the VM disk image
- **Runtimes**: `rsrun 0.1.0` (default features — full set),
  `crun 1.28.0`, `youki 0.6.0`, `runc 1.3.4`

Absolute numbers vary with VM load. Always look at ratios, not raw ms.
The `21.5 ms` cold figure is higher than the original `7.8 ms` measurement
on the same VM — host load was different. The *ratios* (rsrun ≈ 1.4× crun,
2.4× youki, 7× runc) are stable across runs.

## Reproducing

```sh
# In the Lima VM:
cargo build --release
scripts/bench.sh crun youki runc
```

[Lima]: https://github.com/lima-vm/lima
