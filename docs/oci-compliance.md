# OCI compliance

rsrun is tested against the [opencontainers/runtime-tools] validation
suite — the same harness `youki` uses.

## Current status

**16 / 16 passing** on the curated subset rsrun runs in CI:

| Test                          | What it checks                                  |
|-------------------------------|-------------------------------------------------|
| `create`                      | `create` produces a created container           |
| `default`                     | OCI default devices, caps, rlimits, masks       |
| `state`                       | `state` returns the spec-shaped JSON            |
| `kill_no_effect`              | `kill` on a stopped container is a no-op        |
| `killsig`                     | `kill` actually delivers the requested signal   |
| `mounts`                      | bind, tmpfs, proc, sysfs                        |
| `process_capabilities`        | bounding/effective/permitted set correctly      |
| `linux_ns_nopath`             | each namespace gets a fresh inode               |
| `linux_ns_path`               | `setns()` to existing namespaces (incl. PID)    |
| `linux_ns_path_type`          | runtime errors on type/path mismatch            |
| `prestart`                    | OCI prestart hook fires                         |
| `prestart_fail`               | failed prestart hook aborts container           |
| `poststart`                   | OCI poststart hook fires after `start`          |
| `poststart_fail`              | failed poststart is non-fatal (per spec)        |
| `poststop`                    | OCI poststop hook fires during `delete`         |
| `poststop_fail`               | failed poststop is non-fatal                    |

## Reproducing

```sh
# In a Linux VM (Lima, Vagrant, etc.):
cargo build --release
scripts/oci_validation.sh
```

The script clones `opencontainers/runtime-tools` into
`tests/oci-runtime-tests/` on first run, builds the Go test binaries
once, then drives each `.t` against `target/release/rsrun`. Per-case
TAP output lives in `tests/log/`.

Requirements: Go ≥ 1.21, GNU make, sudo, kernel ≥ 5.x with cgroup-v2.

## Notes on what's tested

- **`linux_ns_path`** historically required a 3-process model
  (intermediate task to fork after `setns(CLONE_NEWPID)`). rsrun does
  fork once more on this path only — see [architecture.md](architecture.md).
  The default `create` is still a single fork via `clone3`.
- **`linux_ns_path_type`** is a strict-validation test: the runtime
  must error when a `linux.namespaces[i].path` points to a namespace
  whose actual type doesn't match the declared `type`. rsrun validates
  via `ioctl(NS_GET_NSTYPE)` in the parent before the state directory
  is even created, so the failure surfaces as a non-zero `create`
  exit code.

## What's deliberately not in the curated set

The default `oci_validation.sh` skips cases for features rsrun doesn't
yet implement (see [roadmap.md](roadmap.md)):

- `linux_cgroups_*` — cgroup v1 (rsrun is v2-only)
- Specific cgroup-v2 controllers via runtime-tools' relative paths
- `hooks_stdin.t` — passes `state.json` on stdin in a way the test
  expects byte-for-byte
- `delete_only_create_resources` — depends on cgroup-v1 paths
- `linux_process_apparmor_profile` — needs a specific profile
  pre-installed on the host; works on Ubuntu/Debian images, brittle
  elsewhere
- `linux_rootfs_propagation_*` — mount propagation modes (3 cases of
  319 in `mounts.t` that even crun fails on certain kernels)

Enable them as features land.

[opencontainers/runtime-tools]: https://github.com/opencontainers/runtime-tools
