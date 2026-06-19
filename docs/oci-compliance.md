# OCI compliance

rsrun is tested against the [opencontainers/runtime-tools] validation
suite — the same harness `youki` uses.

The headline goal: **every test that `runc`, `crun`, AND `youki` all
pass, rsrun also passes.**

## Intersection — 12 tests

| Test                          | runc | crun | youki | rsrun |
|-------------------------------|:----:|:----:|:-----:|:-----:|
| `create`                      |  ✅  |  ✅  |  ✅   |  ✅   |
| `default`                     |  ✅  |  ✅  |  ✅   |  ✅   |
| `hostname`                    |  ✅  |  ✅  |  ✅   |  ✅   |
| `kill`                        |  ✅  |  ✅  |  ✅   |  ✅   |
| `kill_no_effect`              |  ✅  |  ✅  |  ✅   |  ✅   |
| `killsig`                     |  ✅  |  ✅  |  ✅   |  ✅   |
| `process`                     |  ✅  |  ✅  |  ✅   |  ✅   |
| `process_capabilities`        |  ✅  |  ✅  |  ✅   |  ✅   |
| `process_user`                |  ✅  |  ✅  |  ✅   |  ✅   |
| `root_readonly_true`          |  ✅  |  ✅  |  ✅   |  ✅   |
| `state`                       |  ✅  |  ✅  |  ✅   |  ✅   |
| `config_updates_without_affect` |  ✅  |  ✅  |  ✅   |  ✅   |

Plus one test where rsrun is stricter than the rest:

| `delete` (must fail when container is not stopped) | ❌ | ❌ | ❌ | ✅ |

`default.t` runs 308 assertions covering the OCI default device set,
default capabilities, default rlimits, masked paths, and readonly paths.

## What's not in the intersection

These are not failed by rsrun *because* they're not in the intersection;
they're failed (or skipped) by at least one of `runc`, `crun`, `youki`
too. rsrun does not implement them yet:

- `linux_ns_path*.t`, `linux_ns_nopath.t` — `setns()` to existing namespaces
- `linux_uid_mappings.t`, `start.t` — these intentionally use
  `Process: nil`; harness behavior on early-error
- `mounts.t` — 3/319 around shared/slave/private propagation
- `delete_only_create_resources.t` — per-container cgroup cleanup
- `linux_cgroups_*.t` — per-container cgroup limits
- `hooks_stdin.t` — OCI hooks
- `linux_seccomp` — seccomp filter loading

## Reproducing

The runtime-tools suite is a Go test binary. Build it from the
[opencontainers/runtime-tools] tree, then point each test at the rsrun
binary the same way you would for `runc`. The `RUNTIME` env var selects
the runtime under test.

[opencontainers/runtime-tools]: https://github.com/opencontainers/runtime-tools
