# Contributing to rsrun

Thanks for your interest. rsrun is at an early stage, so the bar for
contributions is shaped accordingly: small, focused changes are easier
to review and land than sweeping refactors.

## Development

rsrun is Linux-only. The crate uses Linux-only types (`clone3`,
`MsFlags`, `rlimit64`, …) directly without `#[cfg(target_os = "linux")]`
gates — `cargo build` on macOS is expected to fail with type errors,
because the code wouldn't function there even if it compiled.

For development on a macOS / Windows host, run cargo inside a Linux VM.
The project uses [Lima]:

```sh
limactl shell bench   # or whatever VM you set up
cd /path/to/rsrun
cargo build              # debug
cargo build --release    # release (use this for benches)
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test               # 48 unit tests in <1s
scripts/smoke.sh                    # M1 lifecycle smoke (10 checks)
scripts/oci_validation.sh           # OCI runtime-tools (16/16)
scripts/bench.sh crun youki runc    # hyperfine comparison
```

`bash scripts/install-hooks.sh` installs a pre-commit hook that runs
`cargo fmt --all -- --check` on staged Rust files. CI rejects unformatted
PRs, so installing the hook avoids round-trips.

For IDE support on macOS, point rust-analyzer at the Linux target by
adding to `.vscode/settings.json` or your editor's rust-analyzer config:

```json
{ "rust-analyzer.cargo.target": "aarch64-unknown-linux-gnu" }
```

[Lima]: https://github.com/lima-vm/lima

## Reporting bugs

Open an issue with:

1. The `config.json` (or a reduced version) that reproduces the bug.
2. The `rsrun` command line.
3. The kernel version (`uname -r`) and rough rootfs description.
4. Whether `runc` / `crun` reproduces the same behavior on the same
   bundle, if you have them available.

## Sending patches

- One logical change per pull request.
- Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings`
  before pushing.
- Include a brief test plan in the PR description: which `rsrun`
  command(s) you ran, and what behavior you observed.
- For changes to the OCI surface, mention which runtime-tools test
  case the change is motivated by.

## Code style

- Prefer direct syscalls (`libc`) in the child path. After `clone3`
  the child does not allocate.
- Comments should explain **why**, not what — well-named identifiers
  document what.
- New OCI features go through `Spec` (parse) → `Plan` (compile) →
  `runtime_linux` (execute). Keep the layering.

## Security

Please do not open a public issue for security-sensitive bugs. See
[SECURITY.md](SECURITY.md) for the disclosure process.

## License

By submitting a contribution you agree it will be licensed under the
project's license (MIT).
