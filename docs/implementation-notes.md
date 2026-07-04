# Implementation notes

How we built the more-than-trivial features in rsrun, and the
trade-offs each choice carries. Not a tutorial — a record of decisions
made so that future-you (or a reviewer) can see *why* the code looks
the way it does.

The hot path constraint runs through everything: a `create + start +
delete` against an empty bundle must stay in the low-millisecond range.
Every optional feature pays only when its spec field is set.

---

## Joining a pre-existing PID namespace

**Spec:** `linux.namespaces[].path: /proc/<pid>/ns/pid` — the container
init must end up living inside that PID ns.

**Kernel constraint:** `setns(CLONE_NEWPID)` does *not* move the
calling task. It only affects the caller's *future* children.

**youki's solution:** a 3-process model on every `create`
(main → intermediate → init). The intermediate exists specifically so
PID-ns + user-ns transitions can happen in the right order.

**Our solution:** stay 2-process by default; promote to 3-process
*only* when the spec joins a PID namespace by path. The post-clone3
child checks if it joined a PID ns; if so, it forks once more, writes
the grandchild pid back over a relay pipe, and exits. The parent reads
the init pid from that pipe and uses it everywhere. crun does the
same thing in `libcrun/linux.c`.

**Trade-off:** a tiny bit of branch + pipe2 cost on the rare
PID-ns-join path; zero cost on the common path. The whole reason rsrun
beats youki on the bench is that a normal `create` doesn't pay the
3-process tax.

---

## FIFO inheritance across `clone3`

**Problem:** in user-ns + rootless mode, the child's mapped uid can't
traverse `/run/rsrun/<id>/` to open the FIFO — the directory is owned
by host root, and the child sees host-root as `nobody:nogroup`.

**Three options considered:**

1. **`chmod` the state directory open.** Permissive; defeats the
   security intent of state-dir ownership.
2. **Send the FIFO fd over a Unix-domain socket via SCM_RIGHTS.** Works
   but adds a sync round-trip and ~15 LOC.
3. **Pre-open the FIFO in the parent without CLOEXEC; let it inherit
   across clone3.** One LOC change, removes one `open(2)` from the hot
   path.

**We picked (3).** The dropped `open(2)` is worth ~10 µs on the bench;
the new code is half a screen. The cost: one extra fd held by the
parent until clone3 returns, which we close immediately afterward.

---

## Validating namespace path/type pairs

**Spec:** runtime MUST error when `linux.namespaces[i].path` points to
a namespace whose actual kind doesn't match `linux.namespaces[i].type`.

**Naive approach:** rely on the kernel — `setns(fd, CLONE_NEW<type>)`
will EINVAL on mismatch.

**Why that fails:** the kernel call happens in the post-clone3 child.
A child failure surfaces only as a workload-side error written to
`<state>/child.err`; the parent's `rsrun create` returns *success*. The
runtime-tools test (`linux_ns_path_type`) explicitly checks the
*runtime's* exit code.

**Our solution:** validate in the parent, before anything else. Open
each declared path, call `ioctl(fd, NS_GET_NSTYPE)`, compare against
the expected `CLONE_NEW*` constant. Mismatch → return Err from
`cmd_create_full` directly. ~15 LOC. The kernel still does its own
check post-clone3 as a backstop; this is just to make the user-visible
error correct.

---

## Seccomp filter compilation

**Choice:** [`seccompiler`] crate (Firecracker's BPF emitter), not
`libseccomp` and not a hand-rolled emitter.

**Three-way bench on the OCI default profile (~462 syscalls):**

| Library      | Compile time |
|--------------|-------------:|
| hand-rolled  |       229 µs |
| seccompiler  |       419 µs |
| libseccomp   |       799 µs |

**Why we chose seccompiler:** the gap between hand-rolled and
seccompiler is 190 µs, not measurable in the lifecycle bench. The gap
between seccompiler and libseccomp is more than that, so libseccomp is
out. Hand-rolled would be the fastest but adds a maintenance surface
for a feature that runs once per `create`. seccompiler is in active
use by Firecracker (security audits, syscall arg matching coming for
free later).

**Cost:** ~1 MB of crate sources brought in. We accept it because
seccomp is opt-in (no profile → empty `Vec<sock_filter>` → child skips
the prctl entirely).

---

## cgroup v2 only

**Why not v1:** v1 is end-of-life on systemd-cgroup hosts (that's
basically all modern distros except RHEL 8 / Amazon Linux 2). Every
day v1 keeps shrinking. The rules / file paths are ~3× the surface
area of v2. We chose to skip it and document the gap.

**What we lose:** runs on RHEL 8 / older Debian without `--cgroup-no-v1`
on the kernel command line. Workaround for those users: don't use
rsrun yet, or boot with `systemd.unified_cgroup_hierarchy=1`.

**Driver choice:** on `--systemd-cgroup` we shell out to
`systemd-run` (see the dedicated section below). Without the flag we
write cgroupfs directly. Both are supported.

**Process placement:** by default, rsrun writes the init pid to
`cgroup.procs` after `clone3`. `clone3(CLONE_INTO_CGROUP)` is
available only when `RSRUN_CLONE_INTO_CGROUP=1` is set. The opt-in path
opens the target cgroup directory, passes the fd in `CloneArgs.cgroup`,
and skips the post-clone migration when the kernel accepts it. If the
kernel rejects the flag, rsrun retries without it and falls back to
`cgroup.procs`.

**Why opt-in:** the flag can reduce cgroup accounting movement, but the
local lifecycle benchmark showed it slower for `create + start +
delete` with cgroup resources enabled. The default therefore keeps the
measured-faster path; operators who care more about avoiding migration
accounting can enable the flag explicitly.

---

## Device cgroup BPF (hand-rolled emitter)

**Spec:** `linux.resources.devices` — allow/deny rules enforced by a
`BPF_PROG_TYPE_CGROUP_DEVICE` eBPF program attached to the container's
cgroup-v2 directory.

**Three implementations considered:**

| Approach                | New deps                  | LOC   | Verdict              |
|-------------------------|---------------------------|------:|----------------------|
| hand-roll               | none                      |  ~250 | what we did          |
| `rbpf` crate (youki)    | rbpf + libbpf-sys + libbpf | ~1200 | overkill, C dep      |
| `aya`                   | aya + many                |  ~500 | huge transitive deps |
| `libbpf-rs`             | libbpf-rs + libbpf        |  ~300 | C dep again          |

**We picked hand-roll** because the program's instruction shape is
fixed and small. crun (the reference C implementation) hand-rolls
too — ~200 LOC of macro-built `bpf_insn` arrays.

**Program logic:**

```text
prologue (6 insns):
  R3 = ctx->access_type ; R3 >>= 16   → R3 = access bits (1=mknod, 2=read, 4=write)
  R2 = ctx->access_type ; R2 &= 0xffff → R2 = device type (1=block, 2=char)
  R4 = ctx->major
  R5 = ctx->minor

per rule (≤5 insns; wildcards drop their checks):
  if R2 != type, skip          # one BPF_JNE — omitted on type='a'
  if (R3 & ~rule_access), skip # one BPF_JSET — omitted on access='rwm'
  if R4 != major, skip         # omitted on major=-1
  if R5 != minor, skip         # omitted on minor=-1
  R0 = allow ? 1 : 0; EXIT

epilogue (2 insns; emitted only if no wildcard rule was reached):
  R0 = 0; EXIT (default-deny)
```

**Optimizations:**

- `const fn` instruction builders (`ldx_w`, `alu32_imm`, `jmp_imm`,
  …) — zero runtime overhead.
- Single `BPF_JSET` for the access subset check (one insn vs. the
  obvious three of "load → and → jne").
- Stop emitting after a wildcard rule (matches crun's `HAS_WILDCARD`
  flag). Otherwise the verifier rejects unreachable insns.
- Single `Vec` allocation with capacity hint `8 + rules * 5`.

**Implicit allow list.** The OCI-default `[{Allow: false, Access:
"rwm"}]` rule from the runtime-tools generator means "deny all". If we
attached that program before the runtime's own `mknod /dev/null`, the
mknod would fail. So `devices::compile` always **prepends** allow
rules for the six OCI default char devices and for everything in
`linux.devices`. Both runc and crun do the equivalent.

**Wire format gotchas (cost us a debugging session):**

1. `bpf_attr` is a union; the kernel rejects calls with `size >
   sizeof(bpf_attr)` if the trailing bytes are non-zero (E2BIG). Match
   the kernel layout exactly, including the `__u32 :32` padding before
   `fd_array`.
2. `BPF_PROG_TYPE_CGROUP_DEVICE` is enum value **15**, not 9.
   `strace -e bpf` was the fastest way to catch this.
3. `bpf_cgroup_dev_ctx.access_type` encoding is `(access << 16) |
   type`, not the other way around. The xlated bytecode looked
   correct in isolation but blocked everything in practice.
4. Attaching to a non-root cgroup whose ancestor already has a device
   program (systemd's per-service profiles) requires
   `BPF_F_ALLOW_MULTI`. Without it: EINVAL.

**Trade-off:** custom error messages on verifier failure. We capture
the kernel verifier log on EINVAL and surface it in the user-facing
error so the next person who hits a wire-format bug doesn't lose the
same hour we did.

---

## Overlay-backed filesystem state

**Goal:** agent rollout needs cheap reset, diff, branch, and checkpoint
operations without making the normal OCI lifecycle carry extra cost.

**Rootfs backend:** bundles may opt into `rsrun.rootfs.backend =
"overlayfs"`. `create` mounts an overlay with a prepared lower rootfs
and state-owned `upper`, `work`, and `merged` directories. The runtime
persists those paths in `overlay.json` and validates that writable paths
stay under the rsrun state root before reset or cleanup.

**Diff/export:** `changed-files`, `diff`, and `export-diff` scan only
the overlay upperdir. Whiteouts are recognized as either char device
`0:0` or `trusted.overlay.whiteout`; opaque directories use
`trusted.overlay.opaque`. Tar export maps those to `.wh.<name>` and
`.wh..wh..opq`.

**Clone-style snapshots:** `snapshot`, `restore`, and `fork` clone the
recorded upperdir. Regular files try `FICLONE` first and fall back to
copy. Special files, symlinks, ownership, permissions, and xattrs are
preserved best-effort. Size and entry limits prevent accidentally
cloning unbounded state.

**Layer-style checkpoints:** `checkpoint` freezes the current upperdir
as a read-only lower layer. `fork-checkpoint` creates a stopped state
with an empty writable upperdir over the checkpoint chain:

```text
lowerdir = checkpoint_N : checkpoint_N-1 : base
upperdir = new branch upper
```

This avoids per-branch copies when many rollout branches start from the
same checkpoint. Long chains still need policy above rsrun: compact
when lookup cost or mount option length becomes a problem.

**Markers and effects:** `mark` stores a named overlay-diff baseline;
`effects --since <marker> --json` rescans the upperdir and reports the
paths whose metadata changed since that baseline. A marker includes the
overlay reset generation, so effects are rejected after `reset` instead
of returning misleading results.

---

## OCI hooks across all six phases

**Where each phase fires** (this is the bit OCI doesn't make obvious):

| Phase                  | Where                                           |
|------------------------|-------------------------------------------------|
| `prestart` (deprecated)| Parent, before `clone3`                         |
| `createRuntime`        | Parent, before `clone3`                         |
| `createContainer`      | **Inside** the new mount ns, after `pivot_root` |
| `startContainer`       | Inside the new ns, just before `execve`         |
| `poststart`            | Parent, after `start` returns                   |
| `poststop`             | Parent, during `delete`                         |

**Storage between commands.** `create` runs the parent-side hooks then
exits; `start` and `delete` need to fire later phases. We persist the
compiled `Hooks` struct as JSON to `<state-dir>/hooks.json` during
`create`, and `start`/`delete` read it back. The persist step is
skipped entirely when `Hooks::is_empty()`, so containers without hooks
pay zero.

**In-container hooks.** `createContainer` and `startContainer` run
*inside* the child process post-pivot_root. The child has limited
heap state (we haven't done anything that would corrupt it), so we
fork+exec each hook normally; the only constraint is the seccomp
filter, which is installed earlier — so hook binaries must use only
syscalls in the allowed set.

---

## AppArmor / SELinux

**No libapparmor, no libselinux.** Both libraries' "set the next-exec
profile/label" function does the same thing: write to a `/proc/self/
attr/...` pseudo-file. We do the write directly:

| LSM       | Path written                                   | Payload         |
|-----------|------------------------------------------------|-----------------|
| AppArmor  | `/proc/self/attr/apparmor/exec` (5.x kernels)  | `exec <profile>` |
|           | `/proc/self/attr/exec` (legacy fallback)       | `exec <profile>` |
| SELinux   | `/proc/self/attr/exec`                         | `<context>`      |

Both fire right before `execve`. ~50 LOC each, no native dependencies.

**Hard-fail policy.** When `process.apparmorProfile` names a profile
that's not loaded, the child errors out instead of silently running
unconfined. Falling back to unconfined would defeat the policy the
spec asked for. crun and youki behave the same.

---

## `exec` with full OCI semantics

**Initial state:** rsrun's `exec` only honored `args` / `env` / `cwd`.
Everything else from `process.json` was ignored — meaning `docker exec
-u 1000 -t -e FOO=bar mycontainer sh` largely silently misbehaved.

**Now:** `cmd_exec` parses and applies `user.{uid,gid,additionalGids}`,
`capabilities` (all five sets), `noNewPrivileges`, `apparmorProfile`,
`selinuxLabel` — in the same kernel-required order as `child_run`:

```
groups → caps (drop bounding, capset) → setresgid → PR_SET_KEEPCAPS →
setresuid → reapply effective + ambient → noNewPrivs → AppArmor/SELinux
stage → execvpe
```

**Code reuse.** The capability and LSM staging functions
(`apply_capabilities`, `reapply_effective`, `apply_apparmor`,
`apply_selinux`) are unsafe-fn-with-err-fd helpers used by `child_run`.
For `exec` we call them with `err_fd = 2` (stderr) — they write a
diagnostic to stderr and `_exit` on failure. Same code, different
error channel.

**`--console-socket`** is now also wired into `cmd_exec`: when
`process.json` sets `terminal: true` and the engine passes a console
socket, the parent allocates a PTY pair, sends the master fd via
SCM_RIGHTS, and the exec'd child takes the slave as its controlling
terminal. Same `send_pty_master` helper as `create`.

**What we still don't do in exec:** no per-exec seccomp override
(the container's installed filter applies), no `--apparmor` /
`--cap` CLI flag override (the spec'd profile in `process.json` is
what's used), no race-free `--detach` PID guarantee. On the roadmap.

---

## systemd cgroup driver

**The choice:** shell out to `systemd-run --scope` (~25 LOC) instead
of pulling in `zbus` (~50 transitive crates, ~5 MB compile cost) for
a single D-Bus method call.

**Cost:** one fork+exec on `create` *only when `--systemd-cgroup` is
set*. Default rsrun is unaffected. crun does its own D-Bus
marshalling but that's ~400 LOC.

**Trade-off:** we depend on `systemd-run` being on PATH. On any host
where Docker would be configured for `cgroupdriver=systemd`, it is.
On hosts where it isn't, the user gets `cgroupfs` mode anyway —
which is what they would have wanted.

---

## Idmapped mounts

**Spec:** `linux.mounts[].uidMappings` / `gidMappings` (kernel ≥ 5.12)
remap file ownership per-mount without a separate user namespace.

**Kernel constraint:** `MOUNT_ATTR_IDMAP` requires a userns fd —
referencing the mapping — *and* requires the mount to be a freshly-
detached tree (i.e. `open_tree(OPEN_TREE_CLONE)`), not an already-
attached bind. The regular `mount(MS_BIND)` path doesn't work.

**Solution:** for each idmapped mount the parent forks a helper
task that `unshare(CLONE_NEWUSER)`s, writes the requested
`uid_map`/`gid_map`, signals the parent, and pauses. The parent
opens `/proc/<helper>/ns/user`, kills the helper (the userns stays
alive because the fd holds a reference), and passes the fd into the
container child via clone3 inheritance. The child's mount loop calls
the `open_tree` → `mount_setattr(MOUNT_ATTR_IDMAP)` → `move_mount`
triplet for each idmapped entry.

**Trade-off:** one extra fork+kill per idmapped mount, paid only on
bundles that use the feature. Hot path unchanged.

---

## --preserve-fds, --no-pivot, oomScoreAdj

Three small Tier-1 engine-compat flags, all opt-in:

- **`--preserve-fds N`** — the parent walks fds `3..=N+2` and clears
  `FD_CLOEXEC`. clone3+execve then inherit them into the workload.
  Used by systemd socket-activation and podman's pre-bound listener
  injection.
- **`--no-pivot`** — child takes the `chroot(2) + chdir("/")` branch
  instead of the default `pivot_root + umount2(MNT_DETACH)`. Required
  for read-only rootfs setups where pivot_root would fail. The
  pivot_root path is the safer default; chroot is the fallback.
- **`process.oomScoreAdj`** — written from the *parent* to
  `/proc/<init>/oom_score_adj` after clone3 returns. Doing it in the
  child would fail post-userns under PR_SET_DUMPABLE=0 (the child
  can't write its own /proc files).

---

## What we deliberately don't do (yet)

For the full list see [roadmap.md](roadmap.md). Recurring trade-off
themes:

- **cgroup v1**: not worth the surface area for the shrinking install
  base. v2 only.
- **CRIU checkpoint/restore**: complex, niche, and the userland surface
  is large. crun's wrapper is ~1500 LOC.
- **WASM workloads**: youki has it. We don't. Out of scope for v0.
- **CNI / built-in network**: this is engine territory (containerd,
  podman). Runtimes set the netns; engines wire the veth.

[`seccompiler`]: https://github.com/firecracker-microvm/seccompiler
