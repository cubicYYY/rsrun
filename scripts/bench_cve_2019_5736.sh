#!/usr/bin/env bash
# Benchmark CVE-2019-5736 mitigation overhead.
#
# Compares normal protected `create` startup against the same path with
# RSRUN_MEMFD_REEXEC=1, which skips the protected self-reexec. The
# normal fast path uses a read-only cloned `/proc/self/exe` fd; older
# kernels fall back to sealed-memfd self-reexec.
# This isolates the entry-path cost without requiring root or a valid OCI
# bundle; both commands intentionally fail after CLI startup.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUNTIME=${1:-${ROOT}/target/release/rsrun}

if [[ ! -x $RUNTIME ]]; then
  echo "rsrun binary not found at $RUNTIME; build first" >&2
  exit 1
fi
if ! command -v hyperfine >/dev/null 2>&1; then
  echo "hyperfine is required" >&2
  exit 1
fi

hyperfine --ignore-failure --warmup 50 --min-runs 1000 \
  "$RUNTIME create --bundle /tmp/rsrun-no-such-bundle cve-create" \
  "RSRUN_MEMFD_REEXEC=1 $RUNTIME create --bundle /tmp/rsrun-no-such-bundle cve-create"
