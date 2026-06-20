# Gaps vs crun

A point-in-time audit of what crun (the C reference runtime) supports
that rsrun does not. Grouped by likelihood of biting a real Docker /
Podman / Kubernetes user.

For what rsrun *does* implement, see [README.md](../README.md) and
[architecture.md](architecture.md). For features rsrun and crun share
that crun also doesn't ship (e.g. `linux_seccomp` runtime-tools test),
see [oci-compliance.md](oci-compliance.md).

## Tier 1 — likely to bite real workloads

These show up under everyday `docker run` / `podman run` /
Kubernetes-with-containerd flows.

### `--preserve-fds <N>`
- **crun**: `src/run.c:50`, `src/exec.c:81`
- **What**: pass N additional file descriptors (3..N+2) into the
  container. Used by systemd socket-activation, by `podman` to inject
  pre-bound listening sockets, and by some CDI device plugins.
- **rsrun**: argv accepted, value ignored. Engines that hand fds in
  this way will see them silently dropped.

### `--no-pivot`
- **crun**: `src/run.c:55`, `src/create.c:45`
- **What**: skip `pivot_root(2)`, use `chroot(2)` instead. Required for
  read-only rootfs setups (e.g. some embedded / appliance images) and
  for Docker's `--read-only` flag in certain configurations.
- **rsrun**: argv accepted, ignored — rsrun always pivot_roots.

### Idmapped mounts (`mountExtensions.idmap`)
- **crun**: `src/libcrun/linux.c:4413`, `linux.c:328`
- **What**: maps uid/gid ranges per-mount via `mount_setattr(2)`. Used
  by Docker 25+ for rootless remapping, by Kubernetes' user-namespace
  feature gate. OCI field: `linux.mounts[].uidMappings` /
  `gidMappings`. Available since kernel 5.12.
- **rsrun**: not implemented — `linux.mounts[].uidMappings` is parsed
  but the `mount_setattr` call is missing.

### `process.oomScoreAdj`
- **crun**: `src/libcrun/linux.c:3636`
- **What**: writes `/proc/self/oom_score_adj` so the container's init
  has a tunable OOM-kill priority. Kubernetes sets this per pod QoS
  class (Guaranteed = -997, Burstable = depends, BestEffort = +1000).
- **rsrun**: parsed-but-ignored. Affects K8s OOM behavior on pressure.

### cgroup v1
- **crun**: `src/libcrun/cgroup-resources.c:1202` and the v1 subsystem
  files
- **What**: per-controller cgroups under `/sys/fs/cgroup/<controller>/`
  on older kernels / hosts booted without
  `systemd.unified_cgroup_hierarchy=1`.
- **rsrun**: v2 only. RHEL 8, Amazon Linux 2, older Debian default to
  v1.

## Tier 2 — production-relevant, not always

### `process.scheduler` / `linux.scheduler`
- **crun**: `src/libcrun/scheduler.c:146`
- **What**: `SCHED_FIFO`, `SCHED_RR`, `SCHED_DEADLINE`, nice value, RT
  priority, scheduler flags. Applied via `sched_setattr(2)`. Used by
  realtime workloads, latency-sensitive Kubernetes pods, audio /
  video containers.
- **rsrun**: parsed-but-ignored.

### Hook timeout enforcement
- **crun**: `src/libcrun/container.c:817`
- **What**: OCI hooks may declare a `timeout` (seconds); crun kills
  the hook process and fails the container start if it overruns.
- **rsrun**: timeout field is parsed and persisted but **not
  enforced** — a runaway hook hangs `create` forever. Hooks rarely
  set a timeout in practice, but a misbehaving CDI hook will hang
  containerd.

### `linux.sysctl` conflict validation
- **crun**: `src/libcrun/linux.c:3666`
- **What**: rejects `kernel.hostname` if `hostname` field also set;
  rejects sysctls that require a namespace not in the spec; rejects
  non-namespaced sysctls under user-ns.
- **rsrun**: writes whatever's in the map; the kernel's own EACCES /
  EINVAL is the only check. Misconfigured bundles silently get
  partial application.

### `process.consoleSize`
- **crun**: `src/libcrun/terminal.c`
- **What**: initial PTY rows × columns via `TIOCSWINSZ` after PTY
  allocation.
- **rsrun**: parsed-but-ignored — `docker run -it` works but the
  initial size is whatever the kernel default is.

### `process.rlimits[].soft > hard` validation
- **crun**: implicit via `prlimit64` returning EINVAL
- **What**: crun rejects bundles where soft > hard at parse time;
  rsrun accepts and lets the kernel error.
- **rsrun**: relies on kernel; user gets a less helpful error.

### Mount label handling (SELinux)
- **crun**: `src/libcrun/linux.c:2230`
- **What**: chooses between `context=` mount option (mqueue, tmpfs)
  and `setxattr(security.selinux)` (regular fs). Different per
  filesystem.
- **rsrun**: not implemented — sets `process.selinuxLabel` for the
  exec'd process but doesn't propagate `linux.mountLabel` to mount
  points. SELinux-enforcing hosts may see denied accesses on
  bind-mounted volumes.

### `tmpcopyup` mount option
- **crun**: `src/libcrun/linux.c:2212`
- **What**: when bind-mounting *over* an existing directory, first
  copy the directory's contents into the tmpfs (overlayfs-like
  behavior). Used by some K8s ConfigMap / Secret mounts.
- **rsrun**: not implemented.

### Recursive mount propagation flags (`rro`, `rwrw`, …)
- **crun**: `src/libcrun/mount_flags.c:222`
- **What**: per-mount `rro`, `rrw`, `rnoexec`, `rsuid`, etc. — flags
  that propagate to all submounts via `mount_setattr(MOUNT_ATTR_*,
  AT_RECURSIVE)`. Linux 5.12+.
- **rsrun**: parses propagation modes for `rootfsPropagation` but
  not the per-mount `r*` flag set.

## Tier 3 — niche / specialty

### Intel RDT (`linux.intelRdt`)
- **crun**: `src/libcrun/intelrdt.c`
- **What**: writes to `/sys/fs/resctrl/...` to set per-container
  cache and memory-bandwidth class IDs.
- **rsrun**: not implemented. Used in HPC + low-latency trading
  workloads.

### `linux.memoryPolicy` (NUMA)
- **crun**: `src/libcrun/mempolicy.c`
- **What**: `set_mempolicy(2)` for `MPOL_BIND` / `MPOL_INTERLEAVE`
  before exec. NUMA-aware workloads.
- **rsrun**: not implemented.

### `linux.personality`
- **crun**: `src/libcrun/linux.c:1440`
- **What**: `personality(2)` flags (PER_LINUX32 etc.) for ABI
  emulation. Used by 32-bit-on-64-bit chroots.
- **rsrun**: not implemented.

### `process.ioPriority`
- **crun**: `src/libcrun/io_priority.c:49`
- **What**: `ioprio_set(2)` for I/O scheduling class.
- **rsrun**: not implemented.

### AppArmor profile stacking
- **crun**: `src/libcrun/utils.c:926`
- **What**: `change_profile` (stacked) vs `change_onexec`
  (replacement) for container-in-container scenarios with
  pre-existing confinement.
- **rsrun**: only does `change_onexec`. Inner containers fail under
  some AppArmor stacking policies.

## Subcommands rsrun doesn't implement

| Verb | crun source | What |
|---|---|---|
| `ps` | `src/ps.c` | list processes inside a container |
| `mounts` | `src/mounts.c` | dump the container's mount tree (debug) |
| `checkpoint`, `restore` | `src/checkpoint.c`, `src/restore.c` | CRIU integration |
| `spec` | `src/spec.c` | generate a default `config.json` |

`ps` and `mounts` are crun-specific debugging tools — not OCI verbs.
`checkpoint`/`restore` are big features (CRIU dependency, ~1500 LOC
in crun's wrapper alone). `spec` is small and worth implementing for
ergonomics but rarely hit by engines.

## Build / packaging

- **Multi-arch**: `clone3` syscall number is hardcoded for arm64; the
  seccomp x86_64 syscall table for `seccompiler` is not populated by
  rsrun's profile compiler. Need to switch on `target_arch`.
- **Static musl build**: rsrun's release binary links dynamically
  against glibc. crun ships static binaries for 8 architectures.
- **Distro packaging**: no .deb / .rpm / AUR yet; users build from
  source.

## How to use this list

When a user reports a Docker / Podman bug under `--runtime=rsrun`,
check this list first. Most reports fall into one of:

1. cgroup v1 host (Tier 1) → reboot with cgroup v2 unified or
   wait for v1 support.
2. Idmapped mount on a rootless setup (Tier 1) → fall back to runc
   for that container until rsrun ships idmap.
3. K8s QoS scheduling not honored (Tier 2) → known gap; on the
   roadmap.
4. SELinux-enforcing host with bind-mounted volumes (Tier 2) → known
   gap (`mountLabel` not propagated).

Items above with concrete LOC estimates and crun line numbers are the
ones we'd implement next, in roughly this order:

1. `--preserve-fds` (~30 LOC)
2. `--no-pivot` (~20 LOC)
3. `process.oomScoreAdj` (~10 LOC)
4. Hook timeout enforcement (~15 LOC)
5. `linux.sysctl` conflict validation (~30 LOC)
6. `process.consoleSize` (~10 LOC)
7. cgroup v1 (~600 LOC; lower priority)
8. idmapped mounts (~80 LOC; needs kernel ≥ 5.12 detection)
