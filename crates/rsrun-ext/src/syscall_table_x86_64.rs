// Stub: x86_64 syscall table not yet generated. seccomp will silently
// skip rules that target x86_64-only syscalls until this is filled in.
// Tracked in docs/roadmap.md (multi-arch).
#[rustfmt::skip]
fn syscall_nr_x86_64(_name: &str) -> Option<i64> {
    None
}
