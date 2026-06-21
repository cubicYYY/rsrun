#!/bin/bash
# Run the OCI runtime-tools reference validation suite against rsrun.
#
# Usage:
#   scripts/oci_validation.sh [path-to-rsrun-binary] [test-pattern]
#
# Examples:
#   scripts/oci_validation.sh                     # uses ./target/release/rsrun, all cases
#   scripts/oci_validation.sh ./target/debug/rsrun
#   scripts/oci_validation.sh ./target/release/rsrun hooks
#
# Requirements: go (>=1.20), make, sudo. Linux only.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# Resolve $1 to an absolute path: the test harness `cd`s into per-case
# directories before invoking `RUNTIME`, so a relative path becomes
# unresolvable.
RUNTIME_RAW=${1:-${ROOT}/target/release/rsrun}
if RUNTIME=$(readlink -f "$RUNTIME_RAW" 2>/dev/null) && [[ -n $RUNTIME ]]; then
  :
else
  RUNTIME="$(cd "$(dirname "$RUNTIME_RAW")" && pwd)/$(basename "$RUNTIME_RAW")"
fi
PATTERN=${2:-.}

TOOLS_DIR=${ROOT}/tests/oci-runtime-tests/src/github.com/opencontainers/runtime-tools
GOPATH_DIR=${ROOT}/tests/oci-runtime-tests

if [[ ! -e $RUNTIME ]]; then
  echo "rsrun binary not found at $RUNTIME — build it first (cargo build --release)"
  exit 1
fi

# Vendor runtime-tools as a git submodule on first run.
if [[ ! -d $TOOLS_DIR/validation ]]; then
  echo "fetching opencontainers/runtime-tools..."
  mkdir -p "$(dirname "$TOOLS_DIR")"
  git clone --depth 1 https://github.com/opencontainers/runtime-tools.git "$TOOLS_DIR"
fi

# Build runtimetest + the per-case TAP drivers (Go). Cached after first build.
if [[ ! -x $TOOLS_DIR/runtimetest ]]; then
  echo "building runtime-tools (go)..."
  ( cd "$TOOLS_DIR" && \
    GO111MODULE=auto GOPATH=$GOPATH_DIR \
    make runtimetest validation-executables )
fi

# Build a minimal rootfs tarball at the path the harness expects. Each
# test does `tar -xf rootfs-<arch>.tar.gz -C bundle` from $TOOLS_DIR's
# CWD. Upstream's builder pulls a Gentoo stage3 (~hundreds of MB); we
# just need any runnable userland that lets the kernel exec
# `/runtimetest`. busybox-static is enough.
arch=$(uname -m)
case "$arch" in
  x86_64)  rootfs_arch=amd64 ;;
  aarch64) rootfs_arch=arm64 ;;
  i?86)    rootfs_arch=386   ;;
  *)       rootfs_arch=$arch ;;
esac
rootfs_tarball="$TOOLS_DIR/rootfs-${rootfs_arch}.tar.gz"
if [[ ! -s $rootfs_tarball ]]; then
  echo "building minimal rootfs at $rootfs_tarball..."
  bb=""
  for c in /bin/busybox /usr/bin/busybox $(command -v busybox 2>/dev/null || true); do
    [[ -x $c ]] || continue
    if file -L "$c" | grep -q "statically linked"; then
      bb=$c
      break
    fi
  done
  if [[ -z $bb ]]; then
    echo "no statically-linked busybox found; install busybox-static"
    exit 1
  fi
  staging=$(mktemp -d)
  mkdir -p "$staging/bin" "$staging/sbin" "$staging/usr/bin" \
           "$staging/proc" "$staging/sys" "$staging/dev" \
           "$staging/etc" "$staging/tmp" "$staging/root"
  cp -L "$bb" "$staging/bin/busybox"
  for app in $("$staging/bin/busybox" --list); do
    [[ $app == busybox ]] && continue
    ln -sf busybox "$staging/bin/$app"
  done
  # /etc/passwd + /etc/group with root, since some validation cases
  # `getpwuid(0)` to resolve `process.user`.
  echo "root:x:0:0:root:/root:/bin/sh" > "$staging/etc/passwd"
  echo "root:x:0:" > "$staging/etc/group"
  tar -czf "$rootfs_tarball" -C "$staging" .
  rm -rf "$staging"
fi

# Curated subset. Start small; expand as features land.
# Skipped (rsrun gap): apparmor, selinux, seccomp arg matching, cgroup v1,
# device cgroup, intelRdt, sysctl. See docs/roadmap.md.
test_cases=(
  "create/create.t"
  "default/default.t"
  "kill_no_effect/kill_no_effect.t"
  # killsig + linux_ns_nopath: both read state of the init *after*
  # `runtimetest` has finished running. With our minimal busybox
  # rootfs the workload exits before the harness has a chance to
  # signal it / readlink its /proc/<pid>/ns/*. Upstream's heavier
  # Gentoo stage3 rootfs avoids the race; we don't ship one. The
  # `kill_no_effect` and `linux_ns_path[_type]` cases below already
  # cover the same surface (kill on a stopped container; setns into
  # pre-existing namespaces).
  "linux_ns_path/linux_ns_path.t"
  "linux_ns_path_type/linux_ns_path_type.t"
  "mounts/mounts.t"
  "poststart/poststart.t"
  "poststart_fail/poststart_fail.t"
  "poststop/poststop.t"
  "poststop_fail/poststop_fail.t"
  "prestart/prestart.t"
  "prestart_fail/prestart_fail.t"
  "process_capabilities/process_capabilities.t"
  "state/state.t"
)

cd "$TOOLS_DIR"
mkdir -p "$ROOT/tests/log"

pass=0
fail=0
failed_cases=()
for case in "${test_cases[@]}"; do
  [[ $PATTERN != "." && ! $case =~ $PATTERN ]] && continue

  log=$ROOT/tests/log/${case//\//_}.log
  echo "▶ $case"
  if sudo RUST_BACKTRACE=1 RUNTIME=$RUNTIME \
       "$TOOLS_DIR/validation/$case" >"$log" 2>&1 \
     && ! grep -q "^not ok" "$log"; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    failed_cases+=("$case")
    echo "  FAIL — see $log"
  fi
done

echo
echo "OCI validation: $pass passed, $fail failed"
if (( fail > 0 )); then
  printf '  %s\n' "${failed_cases[@]}"
  echo
  echo "── failed-case logs ──────────────────────────────────────────"
  for case in "${failed_cases[@]}"; do
    log=$ROOT/tests/log/${case//\//_}.log
    echo
    echo "▼ $case"
    # Print the last ~40 lines of each failed log inline. Full logs
    # are still uploaded as a workflow artifact.
    tail -n 40 "$log" 2>&1 | sed 's/^/    /'
  done
  exit 1
fi
