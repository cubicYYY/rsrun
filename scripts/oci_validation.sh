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
RUNTIME=${1:-${ROOT}/target/release/rsrun}
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

# Curated subset. Start small; expand as features land.
# Skipped (rsrun gap): apparmor, selinux, seccomp arg matching, cgroup v1,
# device cgroup, intelRdt, sysctl. See docs/roadmap.md.
test_cases=(
  "create/create.t"
  "default/default.t"
  "kill_no_effect/kill_no_effect.t"
  "killsig/killsig.t"
  "linux_ns_nopath/linux_ns_nopath.t"
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
