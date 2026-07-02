# Gaps vs crun

A point-in-time audit of what crun (the C reference runtime) supports
that rsrun does not. Grouped by likelihood of biting a real Docker /
Podman / Kubernetes user.

For what rsrun *does* implement, see [README.md](../README.md) and
[architecture.md](architecture.md). For features rsrun and crun share
that crun also doesn't ship (e.g. `linux_seccomp` runtime-tools test),
see [oci-compliance.md](oci-compliance.md).

## Tier 1 — likely to bite real workloads

Most of this tier has now landed. The remaining gap is cgroup v1.

### `--preserve-fds <N>` ✅ landed
- **crun**: `src/run.c:50`, `src/exec.c:81`
- **rsrun**: marks fds 3..N+2 non-CLOEXEC in the parent before
  clone3 so they inherit into the container init.

### `--no-pivot` ✅ landed
- **crun**: `src/run.c:55`, `src/create.c:45`
- **rsrun**: child uses `chroot(2)` + `chdir("/")` instead of the
  default `pivot_root(2)` + `umount2(MNT_DETACH)` path.

### Idmapped mounts (`linux.mounts[].uidMappings` / `gidMappings`) ✅ landed
- **crun**: `src/libcrun/linux.c:4413`, `linux.c:328`
- **rsrun**: per idmapped mount, the parent forks a helper task that
  unshares a userns and writes the requested uid_map/gid_map into it;
  the parent opens `/proc/<helper>/ns/user` and passes the fd into
  the child via clone3 fd inheritance; the child's mount loop runs
  `open_tree(OPEN_TREE_CLONE)` on the source, applies
  `mount_setattr(MOUNT_ATTR_IDMAP)` with the userns fd, then
  `move_mount`s the detached tree onto the spec target. Linux 5.12+.

### `process.oomScoreAdj` ✅ landed
- **crun**: `src/libcrun/linux.c:3636`
- **rsrun**: written to `/proc/<init_pid>/oom_score_adj` from the
  parent after clone3 returns the host-ns pid.

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
- **rsrun**: ✅ landed. Applied with `sched_setattr(2)` from the parent
  after `clone3`; unknown policies and flags are rejected at parse time.

### Hook timeout enforcement
- **crun**: `src/libcrun/container.c:817`
- **What**: OCI hooks may declare a `timeout` (seconds); crun kills
  the hook process and fails the container start if it overruns.
- **rsrun**: ✅ landed for hooks that declare `timeout`, using
  `pidfd_open` + `poll` where available, then `SIGKILL` + reap on
  deadline. Hooks that omit `timeout` can still block, so runtime-level
  operation timeouts remain an agent-runtime roadmap item.

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

- **Multi-arch**: ✅ landed for CI coverage. Unit tests, lifecycle
  smoke tests, and runtime-tools validation run on x86_64 and aarch64.
- **Static musl build**: rsrun's release binary links dynamically
  against glibc. crun ships static binaries for 8 architectures.
- **Distro packaging**: no .deb / .rpm / AUR yet; users build from
  source.

## How to use this list

When a user reports a Docker / Podman bug under `--runtime=rsrun`,
check this list first. Most reports fall into one of:

1. cgroup v1 host (Tier 1) → reboot with cgroup v2 unified or
   wait for v1 support.
2. SELinux-enforcing host with bind-mounted volumes (Tier 2) → known
   gap (`mountLabel` not propagated).
3. Misconfigured `linux.sysctl` values (Tier 2) → current errors are
   late or partial; parser-side conflict validation is still missing.
4. Initial TTY size or recursive mount flags differ from crun (Tier 2)
   → known compatibility gaps.

Items above with concrete LOC estimates and crun line numbers are the
ones we'd implement next, in roughly this order:

1. `linux.sysctl` conflict validation (~30 LOC)
2. `process.consoleSize` (~10 LOC)
3. `linux.mountLabel` propagation (~40 LOC)
4. `process.rlimits[].soft > hard` validation (~5 LOC)
5. `tmpcopyup` mount option (~25 LOC)
6. Recursive mount propagation flags (~30 LOC; kernel ≥ 5.12)
7. cgroup v1 (~600 LOC; compatibility-driven)
8. Static builds and distro packaging
