#!/usr/bin/env bash
# Regression guard for CVE-2019-5736 mitigation placement.
#
# Benign OCI runtime commands must not pay the protected self-reexec
# cost. Container entry paths (`create` and `exec`) must reexec from a
# protected fd before touching container-controlled state. The fast path
# uses a read-only detached mount fd; the fallback uses a sealed memfd.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUNTIME=${1:-${ROOT}/target/release/rsrun}
WORK=$(mktemp -d /tmp/rsrun-cve-2019-5736.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

if [[ ! -x $RUNTIME ]]; then
  echo "rsrun binary not found at $RUNTIME; build first" >&2
  exit 1
fi
if ! command -v strace >/dev/null 2>&1; then
  echo "strace is required" >&2
  exit 1
fi

features_trace=$WORK/features.trace
strace -e trace=memfd_create,open_tree,mount_setattr,fcntl,execve,execveat \
  "$RUNTIME" features >/dev/null 2>"$features_trace"

if grep -q "memfd_create" "$features_trace"; then
  echo "features unexpectedly used protected reexec" >&2
  cat "$features_trace" >&2
  exit 1
fi

assert_protected_reexec() {
  local name=$1
  shift
  local trace=$WORK/$name.trace

  set +e
  strace -f -e trace=memfd_create,open_tree,mount_setattr,fcntl,execve,execveat \
    "$RUNTIME" "$@" >/dev/null 2>"$trace"
  local status=$?
  set -e

  if [[ $status -eq 0 ]]; then
    echo "$name unexpectedly succeeded; test uses intentionally missing state" >&2
    cat "$trace" >&2
    exit 1
  fi
  if grep -q 'memfd_create("rsrun".*MFD_ALLOW_SEALING' "$trace"; then
    if ! grep -q 'F_ADD_SEALS.*F_SEAL_WRITE' "$trace"; then
      echo "$name did not seal the memfd against writes" >&2
      cat "$trace" >&2
      exit 1
    fi
  elif grep -q 'open_tree(.*"/proc/self/exe".*OPEN_TREE_CLONE' "$trace"; then
    if ! grep -q 'mount_setattr(.*MOUNT_ATTR_RDONLY' "$trace"; then
      echo "$name did not make the cloned binary mount read-only" >&2
      cat "$trace" >&2
      exit 1
    fi
  else
    echo "$name did not create a protected runtime fd" >&2
    cat "$trace" >&2
    exit 1
  fi
  if ! grep -Eq 'execveat\(.*AT_EMPTY_PATH|execve\("/proc/self/fd/' "$trace"; then
    echo "$name did not reexec from the protected fd" >&2
    cat "$trace" >&2
    exit 1
  fi
}

assert_protected_reexec create create --bundle "$WORK/missing-bundle" cve-create
assert_protected_reexec exec exec -p "$WORK/missing-process.json" cve-exec

echo "CVE-2019-5736 regression guard passed"
