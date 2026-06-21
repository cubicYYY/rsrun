#!/usr/bin/env bash
# End-to-end smoke test for rsrun. Exercises the post-M1 surface:
# create/start/delete lifecycle, hook timeout enforcement,
# `process.scheduler`, and crash recovery. Linux + cgroup-v2 + sudo
# required.
#
# Usage:
#   scripts/smoke.sh [path-to-rsrun-binary]
#
# Each subtest writes its bundle and state under /tmp/rsrun-smoke/.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUNTIME=${1:-${ROOT}/target/release/rsrun}
WORK=/tmp/rsrun-smoke
SUDO=${SUDO:-sudo}

if [[ ! -x $RUNTIME ]]; then
  echo "rsrun binary not found at $RUNTIME — build first" >&2
  exit 1
fi
if [[ ! -d /sys/fs/cgroup/cgroup.controllers && ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
  # cgroup v2 unified hierarchy mounts cgroup.controllers as a regular
  # file. v1 hosts won't have it.
  echo "cgroup v2 unified hierarchy required" >&2
  exit 1
fi

$SUDO rm -rf "$WORK"
mkdir -p "$WORK"

# Build a busybox-based rootfs once, reuse for every subtest.
BUNDLE=$WORK/bundle
mkdir -p "$BUNDLE/rootfs/bin"
BB=$(command -v busybox || true)
if [[ -z $BB ]]; then
  echo "install busybox first" >&2
  exit 1
fi
cp -L "$BB" "$BUNDLE/rootfs/bin/busybox"
for app in $("$BUNDLE/rootfs/bin/busybox" --list); do
  [[ $app == busybox ]] && continue
  ln -sf busybox "$BUNDLE/rootfs/bin/$app"
done

write_config() {
  local id=$1 extra=${2:-}
  local args=${3:-'"true"'}
  cat > "$WORK/$id.json" <<JSON
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": [$args],
    "env": ["PATH=/bin"],
    "cwd": "/",
    "capabilities": {
      "bounding":  ["CAP_AUDIT_WRITE"],
      "effective": ["CAP_AUDIT_WRITE"],
      "permitted": ["CAP_AUDIT_WRITE"]
    }
    $extra
  },
  "root": {"path": "rootfs"},
  "hostname": "smoke",
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
     "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"}, {"type": "network"}, {"type": "ipc"},
      {"type": "uts"}, {"type": "mount"}
    ]
  }
}
JSON
  cp "$WORK/$id.json" "$BUNDLE/config.json"
}

pass=0
fail=0
check() {
  local name=$1 cond=$2
  if eval "$cond"; then
    echo "  ok  - $name"
    pass=$((pass+1))
  else
    echo "  FAIL - $name (cond: $cond)"
    fail=$((fail+1))
  fi
}

# ── 1. baseline lifecycle ───────────────────────────────────────────────
echo "== 1. lifecycle =="
write_config base ""
$SUDO $RUNTIME --root $WORK/state.base create -b "$BUNDLE" c1
check "init.pid present"   "[[ -f $WORK/state.base/c1/init.pid ]]"
check "state.json created" "$SUDO grep -q '\"status\":\"created\"' $WORK/state.base/c1/state.json"
$SUDO $RUNTIME --root $WORK/state.base start c1
$SUDO $RUNTIME --root $WORK/state.base delete -f c1
check "state dir removed"  "[[ ! -d $WORK/state.base/c1 ]]"

# ── 2. hook timeout ────────────────────────────────────────────────────
echo "== 2. hook timeout =="
write_config hook ',
    "scheduler": null
  ' '"/bin/sleep", "5"'
# Inject a poststop hook that hangs 30s with a 1s timeout.
python3 - <<EOF
import json, sys
p = "$BUNDLE/config.json"
c = json.load(open(p))
c["hooks"] = {"poststop": [{
  "path": "/usr/bin/sleep",
  "args": ["sleep", "30"],
  "timeout": 1
}]}
json.dump(c, open(p, "w"))
EOF
$SUDO $RUNTIME --root $WORK/state.hook create -b "$BUNDLE" c2
$SUDO $RUNTIME --root $WORK/state.hook start c2
sleep 0.3
t0=$(date +%s.%N)
$SUDO $RUNTIME --root $WORK/state.hook delete -f c2
t1=$(date +%s.%N)
elapsed=$(python3 -c "print(f'{$t1 - $t0:.2f}')")
# Should be ~1s (timeout) + ~0.05s overhead, definitely under 5s.
check "delete killed runaway hook (took ${elapsed}s, want <5s)" \
  "python3 -c 'import sys; sys.exit(0 if $t1 - $t0 < 5 else 1)'"

# ── 3. process.scheduler ────────────────────────────────────────────────
echo "== 3. process.scheduler =="
write_config sched ',
    "scheduler": {"policy": "SCHED_BATCH", "nice": 7}
  ' '"/bin/sleep", "30"'
$SUDO $RUNTIME --root $WORK/state.sched create -b "$BUNDLE" c3
$SUDO $RUNTIME --root $WORK/state.sched start c3
PID=$($SUDO cat $WORK/state.sched/c3/init.pid)
policy=$(awk '{print $41}' /proc/$PID/stat)
nice=$(awk '{print $19}' /proc/$PID/stat)
check "policy is SCHED_BATCH (3)"  "[[ $policy == 3 ]]"
check "nice is 7"                  "[[ $nice == 7 ]]"
$SUDO $RUNTIME --root $WORK/state.sched delete -f c3

# ── 4. crash recovery ──────────────────────────────────────────────────
echo "== 4. crash recovery =="
write_config recov "" '"/bin/sleep", "30"'
$SUDO $RUNTIME --root $WORK/state.recov create -b "$BUNDLE" c4
PID=$($SUDO cat $WORK/state.recov/c4/init.pid)
$SUDO rm $WORK/state.recov/c4/state.json
out=$($SUDO $RUNTIME --root $WORK/state.recov state c4)
check "state synthesizes 'creating'" "echo '$out' | grep -q '\"status\":\"creating\"'"
# delete without -f must refuse
if $SUDO $RUNTIME --root $WORK/state.recov delete c4 2>/dev/null; then
  check "non-force delete refused" "false"
else
  check "non-force delete refused" "true"
fi
$SUDO $RUNTIME --root $WORK/state.recov delete -f c4
check "orphan init killed"  "[[ ! -d /proc/$PID ]]"
check "state dir removed"   "[[ ! -d $WORK/state.recov/c4 ]]"

# ── 5. cleanup ─────────────────────────────────────────────────────────
$SUDO rm -rf "$WORK"

echo
echo "smoke: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
