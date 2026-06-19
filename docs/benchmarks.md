# Benchmarks

rsrun is faster than `crun` and `runc`, and uses less memory.

## Lifecycle latency

`hyperfine` of `create + start + delete` against an OCI bundle that runs
`/bin/true`. `--prepare` drops caches between runs, `--warmup 30`,
`--min-runs 200`.

|         | mean ± σ        | min … max         | vs rsrun |
| ------- | --------------: | ----------------: | -------: |
| rsrun   | **7.8 ms ± 1.3** | 7.0 ms … 15.3 ms  | **1.00×** |
| crun    | 10.7 ms ± 3.4    | 9.6 ms … 52.6 ms  | 1.36×    |
| youki   | 22.9 ms ± 4.8    | 16.4 ms … 36.2 ms | 2.93×    |
| runc    | 126.5 ms ± 3.5   | 122.2 ms … 157.0 ms | 16.15× |

## 100 sequential `/bin/true`

The same shape as crun's headline benchmark — wall-clock time to run 100
containers sequentially that each do `/bin/true`:

|       | 100 × `/bin/true` | vs rsrun |
| ----- | ----------------: | -------: |
| rsrun | **0.692 s**       | **1.00×** |
| crun  | 0.883 s           | 1.28×    |
| youki | 1.595 s           | 2.30×    |
| runc  | 14.403 s          | 20.8×    |

## Memory footprint

Maximum resident set across the full `create + start + delete`
lifecycle, measured with `/usr/bin/time -v`:

|       | max RSS    |
| ----- | ---------: |
| rsrun | **2.1 MB** |
| crun  | 3.4 MB     |
| youki | 6.1 MB     |
| runc  | 11.7 MB    |

## Bench environment

- **Host**: Apple M4, macOS 26.5
- **VM**: [Lima] Ubuntu 22.04.5 LTS, kernel 5.15.0-181-generic, aarch64,
  4 vCPU, 8 GB RAM, `vz` virtualization
- **Filesystem**: ext4 on the VM disk image (binaries and bundle on
  the same partition, no 9p / virtio-fs in the hot path)
- **Runtimes**: `rsrun 0.1.0`, `crun 1.28.0`, `youki 0.6.0`, `runc 1.3.4`

[Lima]: https://github.com/lima-vm/lima
