# Using rsrun as a Docker runtime

Yes — on cgroup-v2 hosts with Docker configured for the cgroupfs
driver, `docker run --runtime=rsrun ...` works end-to-end. Read
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

rsrun handles this layer in `crates/rsrun/src/main.rs`:

- `--root` overrides the state directory.
- `--log` redirects stderr to a file so containerd can recover the
  error message on failure.
- `--log-format json` switches stderr to
  `{"level":"error","time":"...","msg":"..."}` line format that
  containerd's shim parses.
- `--systemd-cgroup`, `--rootless`, `--debug` are accepted (no-op).
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
| Docker daemon configured with `native.cgroupdriver=cgroupfs` | required |
| `BPF_PROG_TYPE_CGROUP_DEVICE` available (kernel ≥ 4.15) | required |
| AppArmor / SELinux profile if your daemon enforces one | works |
| Custom seccomp profile JSON | works |

The two big ones in practice:

### Cgroup driver: cgroupfs vs systemd

Most modern distros' `dockerd.service` is configured with
`native.cgroupdriver=systemd`. **rsrun does not implement the systemd
driver yet** — `--systemd-cgroup` is parsed and ignored, and rsrun
writes cgroupfs directly under `/sys/fs/cgroup/rsrun-<id>/`. Effects:

- The container's cgroup is *not* a systemd transient `.scope`, so it
  does not appear in `systemctl status` and is not subject to systemd's
  OOM/resource policy at the slice level.
- On a host where Docker is otherwise running with `cgroupdriver=systemd`,
  using `--runtime=rsrun` for one container will make that container's
  accounting diverge from the rest.

To use rsrun cleanly, set `"exec-opts": ["native.cgroupdriver=cgroupfs"]`
in `daemon.json` and restart Docker. Or wait for the systemd-cgroup
driver in rsrun (on the roadmap).

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

- **No `pause` / `resume`.** `docker pause` on an rsrun container
  errors out (rsrun doesn't implement the `pause` verb yet).
- **`docker update` doesn't take effect.** rsrun has no `update` verb;
  cgroup limits set at create are sticky.
- **`docker stats`** shows zeros for some columns (rsrun has no
  `events`/`stats` verbs that stream cgroup metrics — Docker falls
  back to reading cgroupfs itself, which works for memory.current but
  not for cpu rates).
- **`docker checkpoint` / `docker restore`** unsupported (no CRIU).
- **`docker exec --tty --interactive`** works for stdin/stdout, but the
  exec'd process inherits the rsrun-side PTY rather than getting its
  own — running `tput`/`top` inside an exec session may misbehave.
- **OCI hooks defined by the engine** (e.g. CDI device hooks injected
  by containerd) fire correctly. Hooks defined in `~/.docker/config.json`
  via `runtime.<name>.runtimeArgs` do *not* — Docker doesn't pass them
  through.

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
