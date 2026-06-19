# Contributing to rsrun

Thanks for your interest. rsrun is at an early stage, so the bar for
contributions is shaped accordingly: small, focused changes are easier
to review and land than sweeping refactors.

## Development

```sh
cargo build           # debug
cargo build --release # release (use this for benches)
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

rsrun is Linux-only. The `cargo` build will succeed on macOS for IDE /
editor support, but the binary errors out at runtime.

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
project's license (Apache-2.0).
