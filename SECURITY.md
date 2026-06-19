# Security policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in rsrun,
please report it privately rather than opening a public GitHub issue.

Send a description including:

- The affected version / commit hash
- A minimal reproducer (config.json, command, kernel version)
- The impact you've observed or believe is possible

We'll acknowledge receipt and work with you on a coordinated
disclosure timeline.

## Scope

In scope:

- Container escapes, host privilege escalation
- Information leaks across the runtime / container boundary
- Denial-of-service against the host from a container the runtime
  was used to launch

Out of scope (today):

- Workload-level isolation gaps that come from features rsrun does
  not yet implement (seccomp, AppArmor, SELinux, OCI hooks). See
  [docs/security.md](docs/security.md) for the current threat model.
