# rsrun

A small, fast OCI runtime in Rust. Drop-in for `runc` / `crun` / `youki` -
the same `create` / `start` / `delete` / `state` / `kill` / `exec` verbs,
the same `config.json`, works as a `docker --runtime=` backend.

The goal is a minimal, readable implementation that focuses on the
syscall-floor cost of the OCI lifecycle.

## Status

Early. Linux-only. No releases yet — build from source. Not
production-ready; some features are not yet thoroughly tested.

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

One fork via `clone3` on the default path; one extra fork only when
joining a PID namespace by path. See
[docs/architecture.md](docs/architecture.md) for the diagram and
syscall sequence.

## What's in tree

- Full lifecycle (`create` / `start` / `delete` / `state` / `kill` /
  `exec` / `list`) plus `pause` / `resume` / `update` / `stats` /
  `events`.
- Rootful + rootless (single user namespace).
- Capabilities, rlimits, default `/dev`, masked + readonly paths,
  `noNewPrivileges`, `process.user`, `oomScoreAdj`.
- seccomp, AppArmor, SELinux.
- cgroup-v2 limits (memory, cpu, pids, io); device cgroup BPF
  (`linux.resources.devices`) via a hand-rolled emitter.
- OCI hooks (all six phases), TTY / `console-socket` for
  `docker run -it`.
- `linux.sysctl`, `linux.rootfsPropagation`,
  `linux.namespaces[].path`, idmapped mounts (kernel 5.12+).
- Engine flags `--systemd-cgroup` (via `systemd-run`),
  `--preserve-fds`, `--no-pivot`.
- Overlay-backed agent state primitives: `reset`, `changed-files`,
  `diff`, `export-diff`, `snapshot`, `restore`, `fork`, `checkpoint`,
  `export-checkpoint`, `import-checkpoint`, `fork-checkpoint`,
  `activate`, `mark`, and `effects`.
- Passes the [opencontainers/runtime-tools] tests in the
  (`runc` ∩ `crun` ∩ `youki`) intersection.
- Works under Docker as `--runtime=rsrun`.

What's not yet implemented: cgroup v1, CRIU checkpoint/restore,
in-runtime network setup (CNI / bridge / veth — engine territory).
See [docs/roadmap.md](docs/roadmap.md) and
[docs/gaps-vs-crun.md](docs/gaps-vs-crun.md) for the full audit.

`CLONE_INTO_CGROUP` is available only as an explicit opt-in:
`RSRUN_CLONE_INTO_CGROUP=1`. The default remains the faster
`cgroup.procs` placement path measured in the lifecycle benchmark.

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
| `rollout`            | rollout overlay state, checkpoints, effects   |

Build Docker-runtime-only binaries without `rollout`; the standard
OCI lifecycle commands do not depend on the rollout command surface.

## Use

Same shape as `runc`:

```sh
rsrun create -b /path/to/bundle myid
rsrun start myid
rsrun delete -f myid
```

State lives at `/run/rsrun/<id>/`. Override with `--root <dir>`.

Overlay-backed state commands are intended for rollout
workflows, not Docker's CRIU checkpoint API:

```sh
rsrun checkpoint myid cp1 --pack overlay2
rsrun export-checkpoint cp1 --format tar > cp1.tar
rsrun import-checkpoint cp1-imported cp1.tar
rsrun fork-checkpoint cp1 branch1 --json
rsrun activate --bundle /path/to/bundle branch1
rsrun start branch1
rsrun exec --json branch1 -- sh -c 'echo step'
rsrun mark branch1 step_10
rsrun effects branch1 --since step_10 --json
```

`activate` turns a stopped fork/import state into a normal created
container. Pass `--bundle` when the checkpoint artifact was imported on
a host where the original bundle path is not valid.

For high-fanout rollout, keep branches stopped until they need CPU or
memory, activate only the branches that are about to run a step, then
delete or checkpoint them according to the controller's retention
policy.

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
- [docs/roadmap.md](docs/roadmap.md) - prioritized list of what we'd
  implement next, with crun source references

## Contributing

Bug reports, design discussion, and patches are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).

[opencontainers/runtime-tools]: https://github.com/opencontainers/runtime-tools
[`seccompiler`]: https://github.com/firecracker-microvm/seccompiler
