# rsrun

A small, fast OCI runtime in Rust. Drop-in for `runc` / `crun` / `youki` -
the same `create` / `start` / `delete` / `state` / `kill` / `exec` verbs,
the same `config.json`, works as a `docker --runtime=` backend.

The goal is a minimal, readable implementation that focuses on the
syscall-floor cost of the OCI lifecycle.

## IMPORTANT NOTE ⚠️

This project is still in its early stages, 
and some features may not have been thoroughly tested. 
Please exercise caution when using it in production.

## Performance

On a `create + start + delete` lifecycle (`hyperfine` against an OCI
bundle running `/bin/true`):

- **Cold cache** (drop_caches between runs): rsrun ~1.4× faster than
  crun, ~2.4× faster than youki, ~7× faster than runc.
- **Warm cache**: rsrun and crun are within ~3 %; both ~2.4× faster
  than youki, ~10× faster than runc.
- **Max RSS**: 2.2 MB (vs crun 3.4 MB, youki 6.0 MB, runc 11.5 MB).

Full numbers, methodology, platform, and reproduce script:
[docs/benchmarks.md](docs/benchmarks.md).

## Process model

```text
parent                                                child
  │
  ├─ mkfifo, pre-open FIFO read-side (O_NONBLOCK)
  │  └─ fd inherits across clone3 (no CLOEXEC)
  ├─ clone3(all NS flags atomic) ──────────────────────►│
  │                                                    ├─ setns paths (if any)
  │                                                    ├─ mount(MS_PRIVATE) on /
  │                                                    ├─ exec mount plan
  │                                                    ├─ pivot_root into rootfs
  │                                                    ├─ sethostname / chdir
  │                                                    ├─ poll(POLLIN) on inherited FIFO fd
  │                                                    │  ◀── blocks until `start`
  │                                                    └─ apply caps/seccomp, execve
  ├─ write /run/rsrun/<id>/init.pid
  ├─ write state.json (status="created")
  └─ exit 0
```

One fork (via `clone3`) on the default path.

The FIFO is opened by the parent and inherited into the child for two
reasons: (1) under user-ns the child's mapped uid can't traverse
`/run/rsrun/<id>/`, which is owned by host root; (2) it removes one
`open(2)` from the hot path.

When `linux.namespaces[].path` joins an existing **PID** namespace,
the child forks once more after `setns(CLONE_NEWPID)` (the kernel
applies that flag only to future children). The intermediate writes
the grandchild pid back over a relay pipe and exits; the grandchild
becomes the real init. crun does the same. The cost is paid only on
that path; default `create` stays at one fork.

## Status

Early. Linux-only. No releases yet - build from source.

What works:

- Full `create` / `start` / `delete` / `state` / `kill` / `exec` lifecycle.
- Rootful and rootless (single user namespace).
- Capabilities, rlimits, default `/dev`, masked + readonly paths,
  `noNewPrivileges`, `process.user` uid/gid transition.
- **seccomp** profile compilation + install (via [`seccompiler`]).
- **cgroup-v2 limits**: memory, swap, CPU (max/weight/cpuset), pids,
  per-device `io.max`.
- **`linux.namespaces[].path`** - join an existing namespace
  instead of creating one (used by `rsrund`'s pre-warmed pool).
- **OCI hooks** - all six phases: `prestart`, `createRuntime`,
  `createContainer`, `startContainer`, `poststart`, `poststop`.
- **TTY / `console-socket`** - `process.terminal: true` allocates a PTY
  pair and sends the master fd over the AF_UNIX socket (SCM_RIGHTS).
- **AppArmor / SELinux** - `process.apparmorProfile` and
  `process.selinuxLabel` staged via `/proc/self/attr/...` for the
  next execve, matching libapparmor / libselinux semantics.
- **Device cgroup BPF** - `linux.resources.devices` allow/deny rules
  compiled to a `BPF_PROG_TYPE_CGROUP_DEVICE` program (~200 LOC,
  hand-rolled, no libbpf) and attached to the container's cgroup-v2
  directory. Default OCI devices and `linux.devices` entries are
  implicitly allowed.
- **`exec` with full OCI semantics** - honors `process.json`'s `user`,
  `capabilities`, `noNewPrivileges`, `apparmorProfile`, `selinuxLabel`,
  `terminal` + `--console-socket`. Applied in the kernel-required
  order (groups -> caps -> user -> NNP -> LSM).
- **`pause` / `resume`** via cgroup-v2 `cgroup.freeze`.
- **`update`** retunes cgroup-v2 limits on a running container.
- **`stats` / `events`** stream cgroup-v2 metrics for `docker stats`.
- **`linux.sysctl`** writes inside the new namespaces.
- **`linux.rootfsPropagation`** (shared/slave/private + recursive).
- **`--systemd-cgroup`** delegates cgroup creation to `systemd-run`
  (transient `.scope` slice).
- Passes the [opencontainers/runtime-tools] tests in the
  (`runc` ∩ `crun` ∩ `youki`) intersection.
- Works under Docker as `--runtime=rsrun`.

What's not done yet:

- cgroup v1 (v2 only)
- Network configuration (netns flag set, no interface setup)
- CRIU checkpoint / restore

These are tracked as future work. See [docs/roadmap.md](docs/roadmap.md).

## Build

```sh
cargo build --release
# target/release/rsrun  (~840 KB with all features)
```

The release profile is tuned for size and startup
(`lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`).

### Feature flags

Every optional capability is a Cargo feature, all enabled by default.
Build a smaller binary by opting out:

```sh
# Minimum: just create/start/delete/state/kill/exec/list (~753 KB)
cargo build --release --no-default-features

# Pick what you need
cargo build --release --no-default-features \
  --features seccomp,cgroup-limits,hooks
```

| Feature              | Adds                                          |
|----------------------|-----------------------------------------------|
| `seccomp`            | OCI seccomp profile (pulls in `seccompiler`)  |
| `cgroup-limits`      | `linux.resources.{memory,cpu,pids,io}` writes |
| `device-cgroup-bpf`  | hand-rolled BPF cgroup-device emitter         |
| `hooks`              | OCI hooks (all six phases)                    |
| `pause`              | `pause` / `resume` verbs                      |
| `update`             | `update` verb                                 |
| `stats`              | `stats` / `events` verbs                      |
| `sysctl`             | `linux.sysctl` writes                         |
| `lsm`                | AppArmor / SELinux exec staging               |
| `systemd-cgroup`     | `--systemd-cgroup` driver via `systemd-run`   |

## Use

Same shape as `runc`:

```sh
rsrun create -b /path/to/bundle myid
rsrun start myid
rsrun delete -f myid
```

State lives at `/run/rsrun/<id>/`. Override with `--root <dir>`.

As a Docker runtime:

```jsonc
// /etc/docker/daemon.json
{
  "runtimes": {
    "rsrun": { "path": "/usr/local/bin/rsrun" }
  }
}
```

```sh
sudo systemctl restart docker
docker run --rm --runtime=rsrun alpine echo hello
```

## Documentation

- [docs/architecture.md](docs/architecture.md) - process model, the
  child code path, the `CompiledPlan` idea
- [docs/implementation-notes.md](docs/implementation-notes.md) - how
  the non-trivial features (PID-ns join, device cgroup BPF, hooks,
  LSMs) were built and the trade-offs each choice carries
- [docs/benchmarks.md](docs/benchmarks.md) - full performance and
  memory-footprint numbers
- [docs/oci-compliance.md](docs/oci-compliance.md) - what the
  `runtime-tools` validation suite says
- [docs/gaps-vs-crun.md](docs/gaps-vs-crun.md) - feature-by-feature
  audit of what crun has that rsrun doesn't, grouped by likelihood
  of biting a real user
- [docs/docker.md](docs/docker.md) - using rsrun as a Docker runtime
- [docs/security.md](docs/security.md) - what's in scope, what isn't,
  CVE-2019-5736 mitigation
- [docs/roadmap.md](docs/roadmap.md) - what v1 will add

## Contributing

Bug reports, design discussion, and patches are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

[opencontainers/runtime-tools]: https://github.com/opencontainers/runtime-tools
[`seccompiler`]: https://github.com/firecracker-microvm/seccompiler
