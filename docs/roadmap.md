# Roadmap

rsrun's hot path is in `rsrun-core` (the lifecycle: clone3, namespaces,
mounts, caps, exec). Heavier features live in `rsrun-ext`, all gated
as default-on Cargo features so the binary can be slimmed by opting
out.

Rollout filesystem/state extensions are gated separately behind the
`rollout` Cargo feature and exported through `rsrun_core::rollout`.
The Docker/OCI runtime surface must remain usable without that feature;
future rollout storage work should keep using this boundary instead of
adding dependencies to the lifecycle hot path.

There are two roadmap tracks:

- **Agent rollout runtime**: [SPEC.md](../SPEC.md) is the primary
  direction for rollout workloads. It prioritizes repeated `exec`,
  bounded failure, structured step results, and filesystem state
  primitives.
- **OCI / crun compatibility**: this file tracks drop-in runtime
  production-readiness. For a feature-by-feature comparison against
  crun, see [gaps-vs-crun.md](gaps-vs-crun.md).

When these tracks conflict, optimize for the agent-runtime hot path
unless a real Docker / containerd / Kubernetes workload proves the
compatibility gap is blocking.

## Agent-runtime priority

These are the next implementation milestones for large-scale agent
rollout use. They intentionally sit ahead of broad crun parity.

### A1 — hardened agent step execution

- First-class `rsrun exec <id> --timeout ... --json -- <cmd> ...`.
- Separate stdout/stderr capture with deterministic truncation.
- Whole-process-tree timeout cleanup, including cgroup cleanup.
- JSON result with exit/signal, timeout, duration, CPU, memory, OOM,
  and output truncation fields.

### A2 — bounded runtime operations

- Runtime-level timeouts for `create`, `start`, `delete`, unmount, and
  cleanup paths.
- Failed cleanup state that is visible to callers and recoverable by a
  later cleanup pass.

### A3 — validation and state primitives

- `validate-bundle <bundle> --json` to reject unsupported bundles
  before a rollout starts.
- ✅ Overlay-backed writable rootfs mode for cheap reset:
  rsrun should own the per-episode overlay upperdir/workdir and state
  metadata, while the lower rootfs remains a prepared OCI bundle path.
  Model this as a writable-rootfs backend so overlayfs is the first
  implementation, not the only possible filesystem strategy.
- ✅ `changed-files`, `diff`, and `export-diff --format tar|json` for
  overlayfs-backed patch extraction.
- ✅ Filesystem-level `snapshot`, `restore`, and `fork` by cloning the
  overlay upperdir with reflink when available and copy fallback; CRIU
  remains a later optional path.
- ✅ High-fanout filesystem checkpoints: `checkpoint` freezes the current
  upperdir as a read-only lower layer, while `fork-checkpoint` creates a
  new branch with an empty writable upperdir over the checkpoint chain.
- Next local-storage gap: pack checkpoint deltas into read-only image
  layers, resolve/mount those layers as lower roots, and compact long
  chains. This closes the single-host layer-format gap without adding
  distributed storage.
- ✅ `mark` and `effects --since <marker> --json` compare current
  overlayfs effects against a named filesystem marker for rollout
  control and debugging.
- ✅ Opt-in `clone3(CLONE_INTO_CGROUP)` for cgroup-v2 placement via
  `RSRUN_CLONE_INTO_CGROUP=1`, with the faster default path retaining
  the previous `cgroup.procs` write.

### Storage scope

Near-term rsrun work should implement overlayfs as the first
writable-rootfs backend. It should support per-episode upperdir/workdir
state, cheap reset, diff, and export while keeping the lower rootfs as a
prepared OCI bundle path.

The implementation should keep a small backend boundary around mount,
diff, export, and cleanup operations so other filesystem strategies can
be added later. The next storage step is local-only packed read-only
layers and compaction; distributed backing stores and Docker
storage-driver integration stay out of scope unless a deployment proves
rsrun itself must prepare those layers.

Build boundary: all rollout-specific filesystem state commands
(`reset`, `diff`, `export-diff`, `snapshot`, `checkpoint`,
`fork-checkpoint`, `mark`, `effects`) belong behind `rollout`.
The OCI lifecycle commands (`create`, `start`, `state`, `kill`,
`delete`, `exec -p`, `pause`, `resume`, `update`, `stats`, `events`)
must continue to compile and run without it.

✅ Rollout filesystem/checkpoint implementation lives in
`rsrun_core::rollout`. `runtime.rs` only calls small rollout hooks
needed by `create`/`delete`; state operations (`reset`, `diff`,
`export-diff`, `snapshot`, `checkpoint`, `fork-checkpoint`, `mark`,
`effects`) stay behind the rollout module boundary. Keep the feature
flag coarse and avoid spreading per-function cfg logic through the
lifecycle hot path.

## Production-readiness — what's still missing

Honest framing of what would have to land before a Docker / containerd
/ Kubernetes operator could safely use `--runtime=rsrun` in production.
Items reference the per-feature detail in the Tier sections below.

### M1 — won't silently break (~3 weeks)

After M1, rsrun is safe to run on a single host where the operator can
monitor it. Without these, real users will hit hangs or silently-wrong
behavior with no diagnostic.

- ✅ **Hook timeout enforcement**. `pidfd_open` + `poll` waits for the
  hook subprocess; on deadline it `SIGKILL`s and reaps. Implemented in
  both parent (`run_hooks`) and in-container (`run_hooks_unsafe`)
  paths. Verified end-to-end: a `poststop` hook of `sleep 30` with
  `timeout: 1` exits the runtime in ~1s instead of hanging for 30s.
  Tier 2 #6.
- ✅ **`process.scheduler`**. `sched_setattr(2)` from the parent on
  the init pid, after clone3. All six policies + 7 flag bits + nice +
  priority + DEADLINE runtime/deadline/period. Verified end-to-end:
  `chrt -p` reports the requested policy; `/proc/<pid>/stat` confirms
  the kernel applied it. Tier 2 #9.
- ✅ **Crash recovery between `create` and `start`**. `init.pid` and
  a `"creating"`-status `state.json` are now written before any
  post-clone3 step that can fail. Failures after clone3 SIGKILL the
  init and tear down the state dir; survival of a parent kill leaves
  a recoverable orphan that `state` reports as `"creating"` and that
  `delete -f` cleans up. Verified end-to-end. Tier 2 #14.
- ✅ **Multi-arch verification on x86_64**. Seccomp x86_64 syscall
  table populated from kernel `syscall_64.tbl` v6.6 (365 names). All
  other direct-syscall sites use `libc::SYS_*` (arch-correct) or
  generic-table numbers shared between aarch64 and x86_64 (`clone3`,
  `open_tree`, `move_mount`, `mount_setattr`). `.github/workflows/ci.yml`
  runs unit tests + lifecycle smoke + runtime-tools validation on both
  `ubuntu-24.04` (x86_64) and `ubuntu-24.04-arm` (aarch64) on every PR.

### M2 — works on the fleet (~6-8 weeks)

After M2, rsrun is a defensible drop-in on the install bases that
matter today: RHEL 8, Amazon Linux 2, K8s clusters with non-default
scheduler classes, SELinux-enforcing hosts.

- **cgroup v1**. ~25-40 % of running fleets depending on the survey.
  Tier 1 #5.
- **`linux.mountLabel`** propagation. Bind volumes on RHEL/Fedora
  fail today. Tier 2 #10.
- **`linux.sysctl` validation**. Misconfigured sysctls silently get
  partial application. Tier 2 #7.
- **Stats accuracy**. `cpu.stat` parsing is partial; `docker stats`
  shows wrong CPU%. ~50 LOC. New.
- **Race-free `docker exec --detach`**. Parent currently can return
  before the child has fully execve'd. CI systems checking liveness
  via `--pid-file` see false negatives. ~30 LOC. New.
- **Richer structured logging**. `--log-format json` emits
  Docker-compatible error lines today; production operators will want
  structured warning/info/debug events with stable fields. Tier 3.

### M3 — stable v1 (open-ended)

After M3, rsrun can claim parity with crun for everything Docker
exercises in practice. Beyond M3 is parity with crun's full surface,
which includes niche features that rarely matter in production
(Intel RDT, NUMA memoryPolicy, personality, ioPriority).

- CRIU integration (live migration / checkpoint).
- AppArmor profile stacking (container-in-container).
- Custom seccomp argument matching (per-syscall `args`).
- `tmpcopyup` mount option (some K8s ConfigMap patterns).
- Recursive mount propagation flags (`rro`, `rrw`, …).
- Distro packaging, signed releases, supply-chain attestation.
- youki `contest` harness alongside runtime-tools in CI (currently
  only the runtime-tools subset under `scripts/oci_validation.sh`
  runs).

### Status disclaimer for the README

The README's "Status" section currently says "Not production-ready;
some features are not yet thoroughly tested." Once the M1 list is
clear, we can replace it with something specific:

> rsrun runs the OCI lifecycle correctly on a single cgroup-v2 host
> with Docker. M1 is complete on aarch64 and x86_64 in CI;
> outstanding before production-on-containerd: cgroup-v1 hosts
> (RHEL 8, AL2), SELinux mount labels, sysctl validation, stats
> accuracy, and race-free detached exec.

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
- Opt-in overlayfs writable rootfs backend via `rsrun.rootfs.backend =
  "overlayfs"` plus `rsrun reset <id>` for stopped containers. The
  runtime records upper/work/merged paths under container state and
  refuses to reset arbitrary host paths.
- Overlayfs-native `changed-files`, `diff`, and `export-diff` walk only
  the recorded upperdir. Deletions are exported as portable tar
  whiteouts; optional text patch generation remains future work.
- Filesystem `snapshot`, `restore`, and `fork` clone only the recorded
  overlay upperdir, preserve overlay metadata, and mount a new stopped
  overlay state without sharing writable files.
- Filesystem `checkpoint` and `fork-checkpoint` avoid per-branch
  checkpoint copies by turning each checkpoint delta into a read-only
  lower layer and giving each rollout branch a fresh empty upperdir.
  Checkpoint metadata records backend, storage format, local layer path,
  and the effective lowerdir chain so another read-only layer store can
  be wired in later.
- Filesystem `mark` and `effects` persist named overlay baselines and
  report post-marker changed paths, sensitive path touches, and
  approximate written bytes. Process, network, and IO accounting remain
  explicit future extensions.
- Local packed checkpoint layers remain the next filesystem-state step:
  checkpoint deltas should be packable into immutable read-only images
  and later resolved into mounted lower roots for `fork-checkpoint`.
- `linux.namespaces[].path` — joining a pre-existing namespace via
  `setns(2)`. PID-ns join works (post-clone3 child re-forks once when
  joining `pid`, mirroring crun).
- `linux.rootfsPropagation` modes (shared / slave / private /
  unbindable + `r*` recursive).
- `linux.sysctl` writes inside the new namespaces.

### Next Storage Milestone — Local Packed Layers

Goal: close the local layer-format gap without introducing distributed
storage. `rsrun` can now commit checkpoint deltas into a runtime-owned
overlay2-style local layer store, export a portable flattened
checkpoint as `tar`, import it on another host, and compose future
branches from those imported roots plus a fresh writable upperdir.
Built-in `tar.zst` compression and multi-layer deduplicated artifacts
remain follow-ups; today callers can compress the exported tar outside
rsrun.

Proposed commands:

```text
rsrun checkpoint <id> <checkpoint-id> --pack directory|overlay2
rsrun export-checkpoint <checkpoint-id> --format tar > checkpoint.tar
rsrun import-checkpoint <checkpoint-id> checkpoint.tar
rsrun fork-checkpoint <checkpoint-id> <new-id>
rsrun compact-checkpoint <checkpoint-id> <new-checkpoint-id>
```

Implementation steps:

1. ✅ Add `LayerRef` metadata with `format = overlay-upperdir |
   flattened-rootfs`, `store = local-directory | overlay2-directory`,
   an optional content digest, and a resolver path.
2. ✅ Keep `--pack directory` as the current default, and add
   `--pack overlay2` using a runtime-owned overlay2-style layout: each
   layer has a `diff/` directory, a `link` file, optional `lower`
   metadata, and a runtime-owned `l/` directory with short symlinks for
   lowerdir mount strings. rsrun does not write into Docker's
   `/var/lib/docker/overlay2`.
3. ✅ Implement `export-checkpoint` / `import-checkpoint` for portable
   `tar` artifacts. The first artifact format is flattened and
   self-contained so it can import on another host without identical
   absolute base-layer paths.
4. ✅ Add a layer resolver that turns `LayerRef` entries into local
   read-only directories or short overlay2 links for `fork-checkpoint`.
5. Implement built-in `tar.zst` artifacts and stronger content digests
   once the compression/digest crate boundary is selected.
6. Implement multi-layer export/import that preserves layer sharing
   when the destination already has the base layers.
7. Add `compact-checkpoint` to materialize a checkpoint chain and pack
   it into one new read-only image when lowerdir count or mount-option
   length crosses a configured threshold.

Acceptance criteria:

- Branch writes never target packed layers.
- Reads from older checkpoint layers do not copy data into the branch
  upperdir.
- Deleted paths survive pack, resolve, fork, and compact through the
  same whiteout semantics used by `export-diff`.
- ✅ A checkpoint exported on one host can be imported on another host and
  forked without editing metadata by hand.
- A chain of at least 100 logical checkpoints can be compacted into a
  bounded number of mounted lower roots before fork. Keep active
  overlay lowerdir chains below Docker overlay2's practical 128-layer
  ceiling and below the mount-option length limit by using short links
  and compaction.
- The default OCI lifecycle path does not mount or inspect checkpoint
  layers.

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

## Tier 1 — gaps that bite everyday users (4/5 landed)

Items 1-4 below are now in tree. The remaining item is cgroup v1.
See [gaps-vs-crun.md](gaps-vs-crun.md) for crun source references.

1. ✅ **`--preserve-fds`** — fds 3..N+2 inherited via `fcntl(F_SETFD,
   !CLOEXEC)` before clone3.

2. ✅ **`--no-pivot`** — child takes the chroot(2) branch instead of
   pivot_root + umount.

3. ✅ **`process.oomScoreAdj`** — written to
   `/proc/<init>/oom_score_adj` from the parent after clone3 returns
   the host pid.

4. ✅ **Idmapped mounts** (`linux.mounts[].uidMappings` /
   `gidMappings`, kernel 5.12+). Helper task per idmap-mount sets up
   a userns with the required mapping; parent opens
   `/proc/<helper>/ns/user` and passes the fd to the child via
   clone3 fd inheritance; child does
   `open_tree(OPEN_TREE_CLONE) → mount_setattr(MOUNT_ATTR_IDMAP) →
   move_mount` on each idmapped entry. Used by Docker 25+ rootless
   remapping and the K8s user-namespace feature gate.

5. **cgroup v1** — RHEL 8, Amazon Linux 2, older Debian. Deferred:
   ~600 LOC duplicating cgroup-v2 logic for v1's per-controller
   layout. Tracked as a separate effort once Tier 2 lands.

## Tier 2 — production-relevant, situational

Items affect real workloads but only under specific configurations.

6. ✅ **Hook timeout enforcement** — `pidfd_open` + `poll` with the
   spec-supplied `hooks[i].timeout`; SIGKILL + reap on deadline.
   Implemented for both parent-side (`run_hooks`) and post-clone3
   in-container (`run_hooks_unsafe`) phases. Falls back to blocking
   wait on kernels without `pidfd_open` (< 5.3).

7. **`linux.sysctl` conflict validation** — reject conflicts with the
   `hostname` field, namespace-required sysctls without the matching
   namespace, etc. crun does this in the spec parser. ~30 LOC.

8. **`process.consoleSize`** — `TIOCSWINSZ` after PTY allocation. PTY
   currently inherits the kernel default rows × cols. ~10 LOC.

9. ✅ **`process.scheduler`** — `sched_setattr(2)` on the init pid
   from the parent after clone3. All six policies, 7 flag bits, plus
   nice / priority / DEADLINE timing fields. Spec rejects unknown
   policies and flags at parse time.

10. **`linux.mountLabel`** propagation — choose `context=` mount
    option vs `setxattr(security.selinux)` per fstype. SELinux hosts
    currently see denied access on bind-mounted volumes. ~40 LOC.

11. **`process.rlimits[].soft > hard` validation** — reject at parse
    time instead of letting the kernel error. ~5 LOC.

12. **`tmpcopyup` mount option** — copy directory contents into tmpfs
    before bind. Used by some K8s ConfigMap / Secret mounts. ~25 LOC.

13. **Recursive mount propagation flags** (`rro`, `rrw`, `rnoexec`,
    `rsuid` …) via `mount_setattr(MOUNT_ATTR_*, AT_RECURSIVE)`.
    Linux 5.12+. ~30 LOC.

14. ✅ **Crash recovery between `create` and `start`**. `init.pid` +
    `state.json("creating")` written immediately after the host pid is
    known, before any fallible post-clone3 step. Failures after that
    point SIGKILL+reap the init and remove the state dir. `cmd_state`
    on a state-less container synthesizes a `"creating"`-or-`"stopped"`
    response from init.pid; `delete -f` cleans up either way.

15. **Stats accuracy**. `cmd_stats` reads `cpu.stat` but parses only
    `usage_usec`; `system_usec` and `user_usec` are dropped, so
    `docker stats` percent-CPU computations are wrong under load.
    Also missing: `memory.events`, `pids.events`. ~50 LOC. M2 item.

16. **Race-free `docker exec --detach`**. Today the parent returns
    after `fork()` regardless of execve completion; if the child's
    apply_capabilities or NNP step fails, the parent's caller sees
    "success" with a child that's about to `_exit`. crun uses an
    extra sync pipe so the parent only returns after `execve` is in
    flight. ~30 LOC. M2 item.

17. **Richer structured logging**. `--log-format json` supports
    Docker-compatible error output today. Add stable structured fields
    for warning/info/debug events and internal operation timing. M2 item.

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
- **Richer log levels / structured logging** — rsrun emits plain or
  Docker-compatible JSON error lines today; broader structured events
  are still missing.
- **Per-container network setup** (CNI / built-in bridge) — engine
  territory; rsrun sets the netns flag and stops there.

## Build / packaging

- ✅ **Multi-arch CI**: `.github/workflows/ci.yml` exercises both
  `ubuntu-24.04` (x86_64) and `ubuntu-24.04-arm` (aarch64) for unit
  tests, the M1 lifecycle smoke (`scripts/smoke.sh`), and OCI
  runtime-tools validation.
- **Static musl build**: release binary links dynamically against
  glibc.
- **Distro packaging**: Debian/Ubuntu .deb, Fedora/RHEL .rpm, AUR.

## Possible directions (perf-focused)

These are speculative. None are blocked on a missing OCI feature.

- **`mimalloc` as global allocator.** Slight startup improvement.
- **`pidfd`-based wait** in `delete` (avoid `/proc/<pid>` polling).
- **Plan cache.** Compile `config.json` once, mmap at create — for
  deployments that launch many copies of the same bundle.

[`seccompiler`]: https://github.com/firecracker-microvm/seccompiler
