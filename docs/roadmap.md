# Roadmap

rsrun's hot path is in `rsrun-core` (the lifecycle: clone3, namespaces,
mounts, caps, exec). Heavier features that don't go in the daemon hot
path live in `rsrun-ext`. Items below are roughly grouped by category;
ordering inside each group is rough priority.

## Now in tree

These don't affect the bench numbers because none of them touch the
`create + start + delete` hot path of an empty bundle.

- **seccomp** filter compilation and install
  (`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`). Backed by
  [`seccompiler`] after a three-way bench against `libseccomp` and a
  hand-rolled BPF emitter on the OCI default profile (462 syscalls).
  Allowlist-by-name only; argument-based matching is on the roadmap.
- **cgroup-v2 limits**: `memory.max`, `memory.swap.max`, `memory.low`,
  `cpu.max`, `cpu.weight`, `cpuset.cpus`, `cpuset.mems`, `pids.max`,
  per-device `io.max`. Honors `linux.resources` from `config.json`.
- **`linux.namespaces[].path`** — joining a pre-existing namespace via
  `setns(2)` instead of creating a fresh one. This is what lets
  `rsrund` use a pre-warmed namespace pool. PID-ns join works for the
  next forked task; callers that need the calling task itself in the
  new pid-ns must re-fork (kernel limitation).
- **OCI hooks**: all six phases. `prestart` / `createRuntime` /
  `poststart` / `poststop` fire from the parent; `createContainer` /
  `startContainer` fire from inside the container's namespaces (after
  pivot_root). Hooks are persisted to `<state-dir>/hooks.json` during
  `create` so `start` and `delete` can read them.
- **TTY / `console-socket`**: when `process.terminal: true` and the
  engine passes `--console-socket`, rsrun allocates a PTY pair via
  `openpty`, sends the master fd to the engine via SCM_RIGHTS, and
  dup2's the slave onto the workload's stdin/stdout/stderr. Makes
  `docker run -it` work end-to-end.
- **AppArmor / SELinux** profile staging. `process.apparmorProfile`
  is written as `"exec <profile>"` to `/proc/self/attr/apparmor/exec`
  (with `/proc/self/attr/exec` as the legacy fallback);
  `process.selinuxLabel` is written to `/proc/self/attr/exec`. The
  kernel then transitions on the next execve. Same path libapparmor /
  libselinux take.
- **Full-fledged `exec`**. `process.json` is parsed for `user`
  (`uid` / `gid` / `additionalGids`), `capabilities` (all five sets),
  `noNewPrivileges`, `apparmorProfile`, `selinuxLabel`, and applied to
  the exec child in the kernel-required order (groups → caps → user
  transition → NNP → LSM staging) before `execve`. Mirrors the
  create-time child path so semantics stay consistent.

## Soon — production-impact gaps vs crun / youki

These are the missing pieces that affect everyday `docker run` /
`podman run` invocations under realistic security profiles.

### Workload isolation

- **Custom seccomp argument matching**. OCI seccomp's per-syscall
  `args` field (compare argument values, not just syscall names).
  Used for filters like "allow `clone()` only without `CLONE_NEWUSER`."
- **Device cgroup BPF** (`linux.resources.devices`). Custom allow / deny
  rules. Today rsrun parses but doesn't enforce; the default cgroup-v2
  device posture is what's active. Need a
  `BPF_PROG_TYPE_CGROUP_DEVICE` emitter.

### Resource control

- **systemd cgroup driver**. Talk to systemd via D-Bus to create
  transient `.scope` slices instead of writing cgroupfs directly.
  Required when `--systemd-cgroup` is set (rsrun accepts the flag and
  ignores it).
- **cgroup v1**. End-of-life on systemd-cgroup hosts but still in use
  on older fleets. Both crun and youki support v1 + v2.
- **More cgroup knobs**: `cpu.idle`, `cpu.uclamp.*`, `memory.peak`,
  `hugetlb.<size>.max`, `rdma.max`, `misc.max`. CPU
  `realtime_runtime` / `realtime_period` for RT scheduling. Niche but
  used.
- **Intel RDT** (`linux.intelRdt`). Cache and memory-bandwidth
  partitioning. crun and youki implement.
- **Network classifier / priorities** (`linux.resources.network`).

### Lifecycle / management

- **`exec` with full OCI semantics**. Today rsrun's `exec` does bare
  setns + fork + execvpe. Need to honor `--cwd`, `--user`, `--env`,
  `--apparmor`, `--cap`, `--no-new-privs`, `-t/--tty` with console
  socket, `--detach`. Required for proper `docker exec`.
- **`pause` / `resume`**. Uses `freezer` cgroup (v1) or
  `cgroup.freeze` (v2). Both crun and youki ship this.
- **`update`**. Modify cgroup limits on a running container.
- **`events`**, **`stats`**. Stream cgroup metrics. crun and youki
  ship both.
- **`spec` subcommand**. Generate a default `config.json`. Currently
  returns "not implemented".

### Spec fields parsed-but-ignored

- **`linux.sysctl`**. Write each `key=value` into `/proc/sys/...`.
- **`process.scheduler`** / **`linux.scheduler`**. `SCHED_FIFO`,
  `SCHED_DEADLINE`, etc.
- **`process.ioPriority`**. `ioprio_set(IOPRIO_WHO_PROCESS, ...)`.
- **`process.consoleSize`**. Set the PTY initial size.
- **`process.rlimits[].soft > hard` validation**. youki/crun reject
  invalid pairs; rsrun accepts.
- **`linux.timeOffsets` / time namespace** (`CLONE_NEWTIME`,
  Linux 5.6+). rsrun doesn't even create the time namespace today.

### Mount features

- **Mount propagation modes** (shared / slave / private / unbindable
  + the `r*` recursive variants). Covered by 3 of the 319 cases in
  `runtime-tools`'s `mounts.t` that rsrun doesn't pass.
- **Idmapped mounts** (`linux.mounts[].uidMappings` /
  `gidMappings`, Linux 5.12+). crun and youki implement.

### Build / packaging

- **Multi-arch**. `clone3` syscall number is hardcoded for arm64;
  the seccomp x86_64 syscall table is empty. Both need filling in.
- **Static musl build**. Currently the release binary links
  dynamically against glibc.
- **Distro packaging**. Debian/Ubuntu .deb, Fedora/RHEL .rpm, AUR.

## Later

- **Per-container network setup** (CNI / built-in bridge). Today
  rsrun sets the netns flag and leaves wiring to the engine.
- **CRIU** checkpoint / restore (`checkpoint`, `restore` subcommands).
- **WASM workloads**. youki has a mode that runs the workload via a
  WebAssembly runtime instead of execve; out of scope for v0 but
  noted for completeness.
- **Annotations passthrough into hook env vars**. crun, runc, and
  youki inject annotation key/value pairs into the environment of
  hook subprocesses.
- **Log levels / structured logging**. crun and youki support log
  levels and structured fields; rsrun emits plain or JSON error-only.

## Possible directions (perf-focused)

- **`mimalloc` as global allocator.** Slight startup improvement.
- **`pidfd`-based wait** in `delete` (avoid `/proc/<pid>` polling).
- **`clone3` with `CLONE_INTO_CGROUP`** to skip the post-fork cgroup
  join write — relevant once cgroup limits are commonly used.
- **Plan cache.** Compile `config.json` once, mmap at create — for
  deployments that launch many copies of the same bundle.

[`seccompiler`]: https://github.com/firecracker-microvm/seccompiler
