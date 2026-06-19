# Security

rsrun is at an early stage. This document is honest about what's in
scope and what isn't.

## Threat model

rsrun assumes:

- **The OCI bundle is trusted.** The host operator who put the
  `config.json` and rootfs in place has authority to run the workload
  with the privileges the spec requests.
- **The kernel is current.** rsrun relies on kernel-level mitigations
  like `deny_write_access` during `execve`.

rsrun does **not** currently defend against:

- A malicious workload trying to escape via seccomp-permitted syscalls.
  rsrun does not load a seccomp filter.
- A malicious workload trying to escape via AppArmor/SELinux gaps.
  rsrun does not apply LSM profiles.
- OCI hook misconfiguration. rsrun does not run hooks.

These are tracked as future work. Until then, do not run untrusted
workloads under rsrun without an additional sandbox layer.

## CVE-2019-5736

[CVE-2019-5736] is a runtime-binary-overwrite attack: a malicious
container can replace the host runtime's on-disk ELF by writing to
`/proc/<runtime_pid>/exe` while the runtime is briefly inside the
container's namespaces during `exec`.

[Background — Palo Alto Unit 42 write-up][unit42].

rsrun's defense has three layers.

### Layer 1: architectural window

`cmd_exec` only puts a brief window between `clone` returning in the
child and the kernel's `execve` succeeding. The parent stays outside
the container's PID namespace; the child becomes visible there only
during the few microseconds of `execve` syscall.

`create` / `start` / `delete` / `state` / `kill` never enter the
container's PID namespace at all. They are immune by construction.

### Layer 2: kernel `deny_write_access`

Modern Linux kernels (≥ 5.x) call `deny_write_access(file)` at the
start of `execve`, setting `i_writecount = -1` on the inode. Any
concurrent `O_WRONLY` open returns `ETXTBSY`. So even if an attacker
catches the race, the write fails.

### Layer 3: `PR_SET_DUMPABLE`

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
