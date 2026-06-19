# Roadmap

rsrun is at an early stage. This is what's planned, roughly in order
of priority.

## Soon

- **seccomp filter loading.** Compile the OCI seccomp profile to BPF
  and install it before `execve`. Required for parity with `crun` /
  `runc` defaults and for any production use.
- **per-container cgroup limits.** Apply `memory.max`, `cpu.max`,
  `pids.max`, etc. from `linux.resources`. Without this `docker run
  --memory ...` does not enforce.
- **OCI hooks.** `prestart` / `createRuntime` / `createContainer` /
  `startContainer` / `poststart` / `poststop`.
- **`exec` parity with `runc`.** Capability-aware exec (so
  `docker exec` with reduced caps works), terminal/console-socket.

## Later

- **AppArmor / SELinux** profile application.
- **Network setup.** Today rsrun sets the netns flag and leaves
  interface configuration to the engine layer. CNI / built-in bridge
  + veth wiring is on the list.
- **CRIU** checkpoint/restore.
- **Joining existing namespaces** via `linux.namespaces[].path` (the
  `linux_ns_path*.t` tests in the runtime-tools suite).

## Build / packaging

- **Static musl build.** Currently the release binary links dynamically
  against glibc.
- **Multi-arch.** Today the `clone3` syscall number is hardcoded for
  arm64; a proper arch dispatch table is needed.
- **Distro packaging.** Debian/Ubuntu .deb, Fedora/RHEL .rpm, AUR.

## Possible directions

- **`mimalloc` as global allocator.** Slight startup improvement.
- **`pidfd`-based wait** in `delete` (avoid `/proc/<pid>` polling).
- **`clone3` with `CLONE_INTO_CGROUP`** to skip the post-fork cgroup
  join write.
- **Plan cache.** Compile `config.json` once, mmap at create — for
  deployments that launch many copies of the same bundle.
