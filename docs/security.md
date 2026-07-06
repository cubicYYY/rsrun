# Security

rsrun is at an early stage. This document is honest about what's in
scope and what isn't.

## Threat model

rsrun assumes:

- **The OCI bundle is trusted.** The host operator who put the
  `config.json` and rootfs in place has authority to run the workload
  with the privileges the spec requests.
- **The kernel is current.** rsrun relies on kernel-level mitigations
  like `deny_write_access` during `execve` and `MOUNT_ATTR_IDMAP`
  (Linux ≥ 5.12 for idmapped mounts).

What rsrun applies when the bundle requests it:

- **seccomp** — `linux.seccomp` profile compiled and installed via
  `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` before exec.
- **AppArmor / SELinux** — `process.apparmorProfile` /
  `process.selinuxLabel` staged via `/proc/self/attr/...`. rsrun
  hard-fails on a missing profile rather than silently running
  unconfined.
- **Device cgroup BPF** — `linux.resources.devices` rules compiled
  to a `BPF_PROG_TYPE_CGROUP_DEVICE` program and attached to the
  cgroup-v2 directory.
- **OCI hooks** — all six phases (`prestart`, `createRuntime`,
  `createContainer`, `startContainer`, `poststart`, `poststop`).
  In-container hooks (`createContainer`, `startContainer`) inherit
  the seccomp filter installed earlier in the child path.

What rsrun **does not** yet defend against:

- Custom seccomp **argument matching** (per-syscall `args`). rsrun
  does allowlist-by-name only; an attacker can still call any
  whitelisted syscall with arbitrary arguments.
- AppArmor profile **stacking** (`change_profile` for
  container-in-container). rsrun does `change_onexec` only.
- Hook **timeouts** are honored only when `hooks[i].timeout` is set
  in the spec. A bundle whose hooks omit `timeout` can still hang the
  runtime; engines that ingest third-party bundles should inject a
  default before invoking rsrun.

The full feature gap audit is in
[gaps-vs-crun.md](gaps-vs-crun.md).

## CVE-2019-5736

[CVE-2019-5736] is a runtime-binary-overwrite attack: a malicious
container can replace the host runtime's on-disk ELF by writing to
`/proc/<runtime_pid>/exe` while the runtime is briefly inside the
container's namespaces during `exec`.

[Background — Palo Alto Unit 42 write-up][unit42].

rsrun's defense has four layers.

### Layer 1: sealed memfd self-reexec

Before the vulnerable entry paths (`create` and `exec`) touch
container-controlled state, rsrun copies its own executable into an
anonymous `memfd`, seals it with `F_SEAL_WRITE`, `F_SEAL_GROW`,
`F_SEAL_SHRINK`, and `F_SEAL_SEAL`, then re-execs from that fd with
`fexecve`.

That means `/proc/<runtime_pid>/exe` points at a sealed anonymous file,
not the host's on-disk `rsrun` binary. Attempts to overwrite, grow, or
truncate the backing executable fail. The fast path uses `sendfile` to
copy `/proc/self/exe` into the memfd; if the kernel rejects `sendfile`,
rsrun falls back to a bounded buffered copy after truncating and
rewinding the memfd. Any partial copy failure fails closed before
`fexecve`.

This mitigation is intentionally scoped to `create` and `exec` so
benign commands such as `features`, `state`, `start`, and `delete` do
not pay the extra startup cost.

### Layer 2: architectural window

`cmd_exec` only puts a brief window between `clone` returning in the
child and the kernel's `execve` succeeding. The parent stays outside
the container's PID namespace; the child becomes visible there only
during the few microseconds of `execve` syscall.

`create` / `start` / `delete` / `state` / `kill` never enter the
container's PID namespace at all. They are immune by construction.

### Layer 3: kernel `deny_write_access`

Modern Linux kernels (≥ 5.x) call `deny_write_access(file)` at the
start of `execve`, setting `i_writecount = -1` on the inode. Any
concurrent `O_WRONLY` open returns `ETXTBSY`. So even if an attacker
catches the race, the write fails.

### Layer 4: `PR_SET_DUMPABLE`

Before `setns`, rsrun calls `prctl(PR_SET_DUMPABLE, 0)`. The kernel
then makes `/proc/<pid>/*` files (including the `/proc/<pid>/exe`
magic symlink) owned by `root:root` of the **initial user namespace**,
regardless of the process's effective UID.

A container process running as namespaced-root but mapped to a
non-zero UID outside the user namespace (the standard rootless layout)
gets `EACCES` from both `readlink` and `open(O_WRONLY)` against
`/proc/<rsrun_pid>/exe`.

Cost: one `prctl` syscall (sub-microsecond, unmeasurable).

**Limitation:** this only protects against attackers in a separate
user namespace. A container sharing the host user namespace with
matching UID 0 = host root would not be blocked — but in that
scenario the workload already has host root, and CVE-2019-5736 is
not the relevant concern.

## Reporting vulnerabilities

If you believe you have found a security vulnerability in rsrun,
please report it privately rather than opening a public issue. See
[SECURITY.md](../SECURITY.md) for the disclosure process.

[CVE-2019-5736]: https://nvd.nist.gov/vuln/detail/CVE-2019-5736
[unit42]: https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/
