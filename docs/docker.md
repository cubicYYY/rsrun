# Using rsrun as a Docker runtime

Yes — `docker run --runtime=rsrun ...` works end-to-end on cgroup-v2
hosts with either the `cgroupfs` or `systemd` cgroup driver. Read
[Compatibility checklist](#compatibility-checklist) before pointing
production traffic at it.

## Setup

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

## How Docker invokes rsrun

Docker delegates to `containerd-shim`, which calls the runtime with this
argv shape:

```
rsrun --root <state-dir> \
      --log <log.json> \
      --log-format json \
      --systemd-cgroup \
      create --bundle <bundle-dir> --pid-file <pid-file> <id>
```

rsrun handles this layer in `crates/rsrun-cli/src/main.rs`:

- `--root` overrides the state directory.
- `--log` redirects stderr to a file so containerd can recover the
  error message on failure.
- `--log-format json` switches stderr to
  `{"level":"error","time":"...","msg":"..."}` line format that
  containerd's shim parses.
- `--systemd-cgroup` switches the cgroup driver from cgroupfs to a
  transient systemd `.scope` slice (via `systemd-run`).
- `--rootless`, `--debug` are accepted (no-op).
- `kill <id>` without an explicit signal (e.g. `docker stop`) defaults
  to `SIGTERM`.
- `features` returns the JSON descriptor Docker queries at registration
  time.

## What works

Verified working as `--runtime=rsrun`:

- `docker run` / `docker stop` / `docker rm` lifecycle, exit code
  propagation, container restart on failure.
- All seven namespaces (`--pid`, `--net`, `--ipc`, `--uts`, `--mount`,
  `--cgroup`, `--user`).
- Capability adjustment (`--cap-add`, `--cap-drop`).
- `--memory`, `--cpus`, `--cpu-shares`, `--pids-limit`, `--blkio-weight`
  on cgroup-v2 hosts (writes `memory.max`, `cpu.max`, `cpu.weight`,
  `pids.max`, `io.max` directly).
- Mounts: bind mounts (`-v`), tmpfs (`--tmpfs`), volumes.
- Hostname (`--hostname`), env (`-e`).
- Interactive TTY (`docker run -it`) — PTY allocation + console-socket
  plumbing (the master fd is sent to containerd via SCM_RIGHTS).
- AppArmor (`--security-opt apparmor=docker-default` and custom
  profiles).
- SELinux (`--security-opt label=...`).
- Seccomp profiles (`--security-opt seccomp=...`).
- OCI device cgroup rules (`--device`, deny-all defaults).
- `--name` reuse after `docker rm`.

## Compatibility checklist

If your host fails any of these, rsrun won't be a drop-in for
`runc` / `crun` on it.

| Check | rsrun support |
|-------|---------------|
| Kernel ≥ 5.x with cgroup v2 unified hierarchy | required |
| `BPF_PROG_TYPE_CGROUP_DEVICE` available (kernel ≥ 4.15) | required |
| AppArmor / SELinux profile if your daemon enforces one | works |
| Custom seccomp profile JSON | works |
| Either `cgroupdriver=cgroupfs` or `cgroupdriver=systemd` | works |
| Idmapped mounts (Docker 25+ rootless remap) | kernel ≥ 5.12 |

### Cgroup version: v1 vs v2

rsrun is **cgroup-v2 only**. RHEL 8 / Amazon Linux 2 / older Debian
boot with cgroup v1 by default. Switch with:

```sh
# /etc/default/grub
GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1"
```

then `update-grub` and reboot. Or wait for v1 support (also on the
roadmap, lower priority).

## Known limitations

- **`docker checkpoint` / `docker restore`** unsupported (no CRIU
  integration). rsrun's `snapshot`, `restore`, `checkpoint`, and
  `fork-checkpoint` commands are filesystem-state primitives for
  stopped overlay-backed states; Docker does not call them.
- **OCI hook timeouts** — honored when `hooks[i].timeout` is set in
  `config.json`. CDI plugins that don't set a timeout still hang
  indefinitely; engines should configure a default per their own
  policy.
- **OCI hooks from `~/.docker/config.json`** via
  `runtime.<name>.runtimeArgs` are not passed through by Docker.
  Hooks on the bundle's `config.json` (which is what containerd /
  CDI-using engines write) fire correctly.

## Quick smoke test

```sh
# Basic: PID/network namespaces, env, exit code propagation
docker run --rm --runtime=rsrun alpine sh -c 'echo $$; exit 42'; echo "exit=$?"
# expected: prints "1" then exit=42

# Cgroup limits
docker run --rm --runtime=rsrun --memory=64m alpine \
  sh -c 'cat /sys/fs/cgroup/memory.max'
# expected: 67108864

# Capability drop
docker run --rm --runtime=rsrun --cap-drop=ALL alpine \
  sh -c 'grep CapEff /proc/self/status'
# expected: CapEff: 0000000000000000

# Device cgroup (deny non-default)
docker run --rm --runtime=rsrun alpine \
  sh -c 'mknod /tmp/foo c 99 99 && echo OK || echo BLOCKED'
# expected: BLOCKED (cgroup BPF rejects mknod outside the OCI defaults)
```
