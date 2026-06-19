# Architecture

rsrun is a 2-process OCI runtime: one parent (the rsrun invocation), one
child (the container init). All namespace setup happens in a single
`clone3` syscall; the child does its own rootfs / mount / capability
work; a FIFO under `/run/rsrun/<id>/` separates `create` from `start`.

## Source layout

```
src/
├── main.rs           CLI dispatch + runc-style global flag parsing
├── spec.rs           config.json → Spec
├── plan.rs           Spec → CompiledPlan (decision-free)
├── clone3.rs         Direct clone3 syscall wrapper
├── runtime.rs        Platform dispatch (Linux vs stub)
├── runtime_linux.rs  Lifecycle implementation
├── runtime_stub.rs   Non-Linux compile-only stubs
└── state.rs          /run/rsrun/<id>/{state.json, init.pid, init.fifo}
```

## Process model

```
parent ──clone3(NEWPID|NEWNS|NEWNET|NEWIPC|NEWUTS|NEWCGROUP[|NEWUSER])──► child
  │                                                                       │
  │                                            [rootless: read 1 byte from sync pipe]
  │                                            ├─ open FIFO RDONLY|NONBLOCK
  │                                            ├─ mount(/, MS_REC|MS_PRIVATE)
  │                                            ├─ bind rootfs onto itself
  │                                            ├─ exec mount plan
  │                                            ├─ /dev mknod + symlinks
  │                                            ├─ masked + readonly paths
  │                                            ├─ pivot_root + chdir(/)
  │                                            ├─ sethostname
  │                                            ├─ chdir(spec.cwd)
  │                                            ├─ poll(POLLIN) on FIFO ◀── waits for `start`
  │                                            ├─ rlimits, caps, user transition,
  │                                            │  no_new_privileges
  │                                            └─ execvpe(argv[0], argv, envp)
  │
  │ [rootless: write uid_map / gid_map / setgroups; signal sync pipe]
  ├─ write /run/rsrun/<id>/init.pid
  ├─ write state.json (status="created")
  └─ exit 0
```

Rootless adds a sync round-trip so the child waits until the parent has
installed `uid_map` / `gid_map`. Rootful skips the pipe entirely; the
hot path takes one predicted-not-taken branch.

`start` opens the FIFO write-side and writes one byte; the child wakes
out of `poll` and proceeds to exec. `delete` sends `SIGKILL` and
`waitpid`s.

## CompiledPlan

The OCI spec is JSON; the kernel takes flags, bitmasks, and
null-terminated C strings. rsrun does that translation **once, in the
parent**, into a flat struct:

```rust
pub struct CompiledPlan {
    pub clone_flags: CloneFlags,       // ready for clone3
    pub wants_userns: bool,
    pub uid_map_data: Vec<u8>,         // pre-formatted "0 1000 1\n"
    pub gid_map_data: Vec<u8>,
    pub hostname: CString,
    pub root_path: PathBuf,
    pub root_readonly: bool,
    pub mounts: Vec<MountOp>,          // each with parsed MsFlags
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    pub cwd: CString,
    pub rlimits: Vec<(__rlimit_resource_t, rlimit64)>,
    pub caps: Option<CapBitmasks>,     // 5 u64 bitmasks
    pub no_new_privileges: bool,
    pub default_devices: Vec<DefaultDevice>,
    pub default_symlinks: Vec<(CString, CString)>,
    pub masked_paths: Vec<CString>,
    pub readonly_paths: Vec<CString>,
    pub user_uid: u32,
    pub user_gid: u32,
    pub user_additional_gids: Vec<u32>,
    pub user_umask: Option<u32>,
}
```

After `clone3`, the child path treats `Plan` as read-only and avoids
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
