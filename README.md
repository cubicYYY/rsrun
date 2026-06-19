# rsrun

A small, fast OCI runtime in Rust. Drop-in for `runc` / `crun` / `youki` —
the same `create` / `start` / `delete` / `state` / `kill` / `exec` verbs,
the same `config.json`, works as a `docker --runtime=` backend.

The goal is a minimal, readable implementation that focuses on the
syscall-floor cost of the OCI lifecycle.

## Status

Early. Linux-only. No releases yet — build from source.

What works:

- Full `create` / `start` / `delete` / `state` / `kill` / `exec` lifecycle.
- Rootful and rootless (single user namespace).
- Capabilities, rlimits, default `/dev`, masked + readonly paths,
  `noNewPrivileges`, `process.user` uid/gid transition.
- Passes the [opencontainers/runtime-tools] tests in the
  (`runc` ∩ `crun` ∩ `youki`) intersection.
- Works under Docker as `--runtime=rsrun`.

What's not done yet:

- seccomp, AppArmor, SELinux, OCI hooks
- per-container cgroup limits (the namespace flag is set, no
  `memory.max` / `cpu.max` writes)
- network configuration (netns flag set, no interface setup)
- terminal/TTY allocation, `console-socket`
- CRIU checkpoint/restore

These are tracked as future work. See [docs/roadmap.md](docs/roadmap.md).

## Build

```sh
cargo build --release
# target/release/rsrun
```

The release profile is tuned for size and startup
(`lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`).

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

- [docs/architecture.md](docs/architecture.md) — process model, the
  child code path, the `CompiledPlan` idea
- [docs/oci-compliance.md](docs/oci-compliance.md) — what the
  `runtime-tools` validation suite says
- [docs/docker.md](docs/docker.md) — using rsrun as a Docker runtime
- [docs/security.md](docs/security.md) — what's in scope, what isn't,
  CVE-2019-5736 mitigation
- [docs/roadmap.md](docs/roadmap.md) — what v1 will add

## Contributing

Bug reports, design discussion, and patches are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

[opencontainers/runtime-tools]: https://github.com/opencontainers/runtime-tools
