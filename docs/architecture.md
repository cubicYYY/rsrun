# Architecture

rsrun is a 2-process OCI runtime: one parent (the rsrun invocation), one
child (the container init). All namespace setup happens in a single
`clone3` syscall; the child does its own rootfs / mount / capability
work; a FIFO under `/run/rsrun/<id>/` separates `create` from `start`.

## Workspace layout

```
rsrun/
└── crates/
    ├── rsrun-core/   (lib, depended on by both rsrun and rsrund)
    ├── rsrun-ext/    (lib, depended on by rsrun only)
    └── rsrun/        (bin)
```

- **`rsrun-core`** holds the syscall-floor lifecycle: `clone3`,
  namespaces, mounts, `pivot_root`/`chroot`, capabilities, rlimits,
  default `/dev`, LSM staging, `noNewPrivileges`, `process.user`,
  `linux.sysctl`, idmapped mounts, the full `exec` verb, and the
  `pause` / `resume` / `update` / `stats` / `events` verbs.
- **`rsrun-ext`** holds the spec → plan compilation that pulls in
  external crates: seccomp (`seccompiler`), cgroup-v2 knob writes,
  OCI hooks, the eBPF emitter for `linux.resources.devices`. Each is
  a Cargo feature; an empty `ExtPlan` makes core skip the
  corresponding install step.
- **`rsrun` (bin)** orchestrates: parse argv, load the spec, ask
  `rsrun-ext` to build an `ExtPlan` from the spec extras, hand it to
  `rsrun-core::cmd_create_full`.

Every optional capability is a default-on Cargo feature — see the
"Feature flags" table in [README.md](../README.md). Building with
`--no-default-features` produces a 753 KB binary that just does the
lifecycle.

The future `rsrund` daemon depends only on `rsrun-core` and passes
`ExtPlan::default()` to skip the heavy work — its trust model
(pre-warmed namespaces, trusted agents) doesn't need per-container
seccomp / cgroup limits / hooks.

## Source files

```
crates/rsrun-core/src/
├── lib.rs       crate root + public API re-exports
├── spec.rs      config.json → Spec
├── plan.rs      Spec → CompiledPlan (decision-free) + ExtPlan
├── clone3.rs    Direct clone3 syscall wrapper
├── runtime.rs   Lifecycle implementation (single Linux file)
└── state.rs     /run/rsrun/<id>/{state.json, init.pid, init.fifo, hooks.json}

crates/rsrun-ext/src/
├── lib.rs       composes spec → ExtPlan
├── seccomp.rs   OCI seccomp profile → BPF (via seccompiler)
├── cgroup.rs    OCI resources → cgroup-v2 file writes
├── devices.rs   OCI device rules → eBPF (BPF_PROG_TYPE_CGROUP_DEVICE)
└── hooks.rs     OCI hooks → HookCmd entries
```

Linux-only (no cfg gates, no stubs). For dev on non-Linux hosts, run
cargo inside a Lima/Vagrant VM.

## Process model

Default 2-process path (one fork via `clone3`):

```
parent                                                child
  │
  ├─ mkfifo + pre-open FIFO RDONLY|NONBLOCK
  │  └─ fd inherits across clone3 (no CLOEXEC)
  ├─ create cgroup dir + write knobs + attach device BPF
  ├─ fire createRuntime + prestart hooks
  ├─ clone3(all NS flags atomic) ────────────────────►│
  │                                                   ├─ [rootless: read sync pipe]
  │                                                   ├─ setns paths (if any)
  │                                                   ├─ mount(/, MS_REC|MS_PRIVATE)
  │                                                   ├─ bind rootfs onto itself
  │                                                   ├─ exec mount plan
  │                                                   ├─ pivot_root + chdir(/)
  │                                                   ├─ sethostname / chdir
  │                                                   ├─ /dev mknod + symlinks
  │                                                   ├─ masked + readonly paths
  │                                                   ├─ poll(POLLIN) on FIFO  ◀── waits for `start`
  │                                                   ├─ rlimits, caps, user
  │                                                   ├─ no_new_privileges
  │                                                   ├─ seccomp install
  │                                                   ├─ AppArmor/SELinux stage
  │                                                   ├─ startContainer hooks
  │                                                   └─ execvpe(argv[0], argv, envp)
  │
  │ [rootless: write uid_map / gid_map / setgroups; signal sync pipe]
  ├─ write /run/rsrun/<id>/init.pid + state.json
  └─ exit 0
```

The FIFO is parent-opened and the read-fd is inherited into the child.
Two reasons: (1) under user-ns, the child's mapped uid can't traverse
`/run/rsrun/<id>/` (host-root-owned); (2) saves one `open(2)` from the
hot path.

`start` opens the FIFO write-side and writes one byte; the child wakes
out of `poll` and proceeds to exec. `delete` sends `SIGKILL` and
`waitpid`s.

### 3-process path (only on PID-ns join by path)

When `linux.namespaces[].path` joins an existing PID namespace, the
child must fork *once more* after `setns(CLONE_NEWPID)` because that
flag only takes effect for the caller's future children. rsrun
allocates a small relay pipe before clone3; the intermediate writes the
grandchild's host-ns pid back over it and exits, the parent reads the
pid and uses it as the recorded init. Same shape crun uses
(`libcrun/linux.c`, `idx_pidns_to_join_immediately`). The default path
stays at one fork.

## CompiledPlan

The OCI spec is JSON; the kernel takes flags, bitmasks, and
null-terminated C strings. rsrun does that translation **once, in the
parent**, into a flat struct (`crates/rsrun-core/src/plan.rs`):

- Namespace flags pre-OR'd for `clone3`, with `wants_userns` so the
  rootless path is a single predicted-not-taken branch.
- uid_map / gid_map already formatted as line buffers.
- `MountOp` per spec mount with `MsFlags` parsed and `data` as a
  pre-built `CString`; idmap mappings pre-formatted per mount.
- argv / envp / cwd as `Vec<CString>`.
- Capability bitmasks (5 `u64`), rlimits as `(resource, rlimit64)`
  pairs.
- Default `/dev` device + symlink lists as `CString`s.
- LSM stage strings (AppArmor profile, SELinux label) as `CString`s.
- `linux.sysctl` writes pre-resolved to `(/proc/sys/<path>, value)`.
- `ExtPlan` opt-in payload: seccomp BPF, cgroup-v2 knob writes, hooks,
  device cgroup eBPF.

After `clone3`, the child path treats the plan as read-only and avoids
the heap. Everything is a syscall on data that's already shaped for
the kernel.

## clone3 directly

`nix`'s `clone3` is gated and unsafe with extra rules. rsrun calls the
syscall directly with a `#[repr(C)]` `CloneArgs`:

```rust
clone3(CloneArgs {
    flags: CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC
         | CLONE_NEWNET | CLONE_NEWCGROUP
         | (rootless ? CLONE_NEWUSER : 0)
         | CLONE_PIDFD,
    exit_signal: SIGCHLD,
    pidfd: &pidfd_out,
    ..
});
```

This is what lets rsrun stay 2-process: the child becomes PID 1 of the
new pid-ns directly, no intermediate fork needed.

## Capabilities

Linux capability handling around a uid transition is the fiddly part.
The order rsrun uses, for non-root user:

1. `setgroups` + `umask` (still root, full caps)
2. `PR_CAPBSET_DROP` for caps not in `bounding`
3. `capset` for `permitted` / `effective` / `inheritable`
4. `PR_CAP_AMBIENT_RAISE` for each ambient cap
5. `setresgid`
6. `PR_SET_KEEPCAPS` so `setresuid` preserves permitted
7. `setresuid`
8. `capset` again to rebuild `effective` (KEEPCAPS clears it)
9. `PR_CAP_AMBIENT_RAISE` again (setresuid clears ambient)
10. `PR_SET_NO_NEW_PRIVS`
11. `execvpe`

For root user (uid 0 → uid 0), steps 5-9 are skipped. `capset` is
called via direct syscall — no `libcap` dependency.

## /dev population

The OCI default device set is created with `mknod` (and a bind-mount
fallback when `mknod` is denied):

- Char devices: `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`,
  `/dev/urandom`, `/dev/tty`
- Symlinks: `/dev/fd → /proc/self/fd`, `/dev/{stdin,stdout,stderr} → fd/{0,1,2}`,
  `/dev/ptmx → pts/ptmx`

`mknod`'s `mode` argument is masked by the process umask. With Docker's
default 022, `0666` becomes `0644`. rsrun wraps the `mknod` calls in
`umask(0)` and follows up with `chmod` to enforce the spec mode.
