# Roadmap

rsrun's hot path is in `rsrun-core` (the lifecycle: clone3, namespaces,
mounts, caps, exec). Heavier features live in `rsrun-ext`, all gated
as default-on Cargo features so the binary can be slimmed by opting
out.

For a comprehensive feature-by-feature comparison against crun, see
[gaps-vs-crun.md](gaps-vs-crun.md). This file lists the priority order
for what we'd implement next.

## Now in tree

These don't affect the bench numbers because none of them touch the
`create + start + delete` hot path of an empty bundle.

### Lifecycle / verbs
- Full `create` / `start` / `delete` / `state` / `kill` / `exec` /
  `list` / `features` lifecycle.
- `pause` / `resume` (cgroup-v2 `cgroup.freeze`).
- `update` re-tunes cgroup-v2 limits on a running container.
- `stats` / `events` stream cgroup-v2 metrics for `docker stats`.

### Namespaces / mounts
- All seven namespaces; rootful and rootless (single user namespace).
- `linux.namespaces[].path` — joining a pre-existing namespace via
  `setns(2)`. PID-ns join works (post-clone3 child re-forks once when
  joining `pid`, mirroring crun).
- `linux.rootfsPropagation` modes (shared / slave / private /
  unbindable + `r*` recursive).
- `linux.sysctl` writes inside the new namespaces.

### Process / security
- Capabilities (all five sets), rlimits, default `/dev`, masked +
  readonly paths, `noNewPrivileges`, `process.user` uid/gid + supp gids.
- **seccomp** profile compilation + install (via [`seccompiler`]).
- **AppArmor / SELinux** profile staging via `/proc/self/attr/...`
  for the next execve.
- **`exec` with full OCI semantics**: honors `process.json`'s `user`,
  `capabilities`, `noNewPrivileges`, `apparmorProfile`, `selinuxLabel`,
  `terminal` + `--console-socket`. Order matches `child_run`
  (groups → caps → user → NNP → LSM).

### Resources
- **cgroup-v2 limits**: `memory.{max,swap.max,low}`, `cpu.{max,weight}`,
  `cpuset.{cpus,mems}`, `pids.max`, per-device `io.max`.
- **Device cgroup BPF** (`linux.resources.devices`): hand-rolled eBPF
  emitter compiles allow/deny rules to a `BPF_PROG_TYPE_CGROUP_DEVICE`
  program. OCI defaults + `linux.devices` entries are implicitly
  allowed. ~250 LOC, zero new crate deps.
- **`--systemd-cgroup`** delegates cgroup creation to `systemd-run`
  (transient `.scope` slice).

### Engine integration
- **OCI hooks**: all six phases. `prestart` / `createRuntime` /
  `poststart` / `poststop` fire from the parent; `createContainer` /
  `startContainer` fire from inside the container's namespaces.
- **TTY / `console-socket`**: PTY pair + SCM_RIGHTS forward — makes
  `docker run -it` and `docker exec -it` work end-to-end.
- **Cargo features**: every optional capability gated; default = full
  set, `--no-default-features` produces a 753 KB minimum binary.

## Soon — gaps that affect everyday users

In rough priority order. See
[gaps-vs-crun.md](gaps-vs-crun.md) for full context and crun source
references for each item.

1. **`--preserve-fds`** — pass extra fds into the container init.
   Used by systemd socket-activation, podman socket injection, some
   CDI plugins. Currently parsed-and-ignored. ~30 LOC.

2. **`--no-pivot`** — skip pivot_root, use chroot. Required for
   read-only rootfs and embedded images. ~20 LOC.

3. **`process.oomScoreAdj`** — write `/proc/self/oom_score_adj`.
   Kubernetes sets this per pod QoS class; affects OOM-kill
   priority under memory pressure. ~10 LOC.

4. **Hook timeout enforcement** — kill hook subprocess after
   `hooks[i].timeout` seconds. A misbehaving CDI hook currently hangs
   `create` forever. ~15 LOC.

5. **`linux.sysctl` conflict validation** — reject conflicts with the
   `hostname` field, namespace-required sysctls without the matching
   namespace, etc. crun does this in the spec parser. ~30 LOC.

6. **`process.consoleSize`** — `TIOCSWINSZ` after PTY allocation. PTY
   currently inherits the kernel default rows × cols. ~10 LOC.

7. **`process.scheduler`** — `SCHED_FIFO` / `SCHED_RR` /
   `SCHED_DEADLINE` via `sched_setattr(2)`. Realtime workloads,
   K8s latency-sensitive pods. ~50 LOC.

8. **`linux.mountLabel`** propagation — choose `context=` mount
   option vs `setxattr(security.selinux)` per fstype. SELinux hosts
   currently see denied access on bind-mounted volumes. ~40 LOC.

9. **Idmapped mounts** (`linux.mounts[].uidMappings` /
   `gidMappings`, kernel 5.12+) — `mount_setattr(MOUNT_ATTR_IDMAP)`.
   Used by Docker 25+ rootless remapping and the K8s user-namespace
   feature gate. ~80 LOC + kernel-version detection.

10. **cgroup v1** — RHEL 8, Amazon Linux 2, older Debian. ~600 LOC
    duplicating cgroup-v2 logic for v1's per-controller layout.
    Diminishing return.

## Later

- **`spec` subcommand** — generate a default `config.json`. Currently
  returns "not implemented".
- **Custom seccomp argument matching** — OCI seccomp's per-syscall
  `args` field. Used for filters like "allow `clone()` only without
  `CLONE_NEWUSER`."
- **AppArmor profile stacking** — `change_profile` (stacked) vs
  `change_onexec`; for container-in-container scenarios.
- **More cgroup-v2 knobs** — `cpu.idle`, `cpu.uclamp.*`,
  `memory.peak`, `hugetlb.<size>.max`, `rdma.max`, `misc.max`.
- **Intel RDT** (`linux.intelRdt`) — HPC / trading workloads.
- **`linux.memoryPolicy`** — NUMA `MPOL_BIND` / `MPOL_INTERLEAVE`.
- **`linux.personality`** — 32-bit ABI emulation.
- **`process.ioPriority`** — `ioprio_set(2)`.
- **`linux.timeOffsets` / time namespace** (`CLONE_NEWTIME`).
- **CRIU** checkpoint / restore.
- **WASM workloads** — youki has it; out of scope for now.
- **Annotations passthrough** into hook env vars.
- **Log levels / structured logging** — rsrun emits plain or JSON
  error-only.
- **Per-container network setup** (CNI / built-in bridge) — engine
  territory; rsrun sets the netns flag and stops there.

## Build / packaging

- **Multi-arch**: `clone3` syscall number hardcoded for arm64; the
  seccomp x86_64 syscall table is not populated. Need to switch on
  `target_arch`.
- **Static musl build**: release binary links dynamically against
  glibc.
- **Distro packaging**: Debian/Ubuntu .deb, Fedora/RHEL .rpm, AUR.

## Possible directions (perf-focused)

These are speculative. None are blocked on a missing OCI feature.

- **`mimalloc` as global allocator.** Slight startup improvement.
- **`pidfd`-based wait** in `delete` (avoid `/proc/<pid>` polling).
- **`clone3` with `CLONE_INTO_CGROUP`** to skip the post-fork cgroup
  join write — relevant once cgroup limits are commonly used.
- **Plan cache.** Compile `config.json` once, mmap at create — for
  deployments that launch many copies of the same bundle.

[`seccompiler`]: https://github.com/firecracker-microvm/seccompiler
