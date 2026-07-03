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

# Build a busybox-based rootfs once, reuse for every subtest. We need
# a *statically linked* busybox: the rootfs has no glibc, so a dynamic
# binary would die on execve with ENOENT-on-the-loader. Ubuntu's
# `busybox` package is dynamic; `busybox-static` is what we want, and
# it lives at /bin/busybox.
BUNDLE=$WORK/bundle
mkdir -p "$BUNDLE/rootfs/bin"
BB=""
for c in /bin/busybox /usr/bin/busybox $(command -v busybox 2>/dev/null || true); do
  [[ -x $c ]] || continue
  if file -L "$c" | grep -q "statically linked"; then
    BB=$c
    break
  fi
done
if [[ -z $BB ]]; then
  echo "no statically-linked busybox found; install busybox-static" >&2
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

# ── 0. validate-bundle ─────────────────────────────────────────────────
echo "== 0. validate-bundle =="
write_config validate ""
python3 - <<EOF
import json
p = "$BUNDLE/config.json"
c = json.load(open(p))
c.setdefault("linux", {})["mountLabel"] = "system_u:object_r:container_file_t:s0"
c["process"]["consoleSize"] = {"height": 24, "width": 80}
json.dump(c, open(p, "w"))
EOF
validate_json=$WORK/validate.json
if $RUNTIME validate-bundle "$BUNDLE" --json > "$validate_json" 2>/dev/null; then
  check "validate-bundle rejects unsupported bundle" "false"
else
  check "validate-bundle rejects unsupported bundle" \
    "python3 -c 'import json,sys; j=json.load(open(\"$validate_json\")); sys.exit(0 if j[\"supported\"] is False and any(\"mountLabel\" in r for r in j[\"reasons\"]) else 1)'"
fi

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

write_config create_timeout "" '"/bin/sleep", "30"'
python3 - <<EOF
import json
p = "$BUNDLE/config.json"
c = json.load(open(p))
c["hooks"] = {"createRuntime": [{
  "path": "/usr/bin/sleep",
  "args": ["sleep", "30"]
}]}
json.dump(c, open(p, "w"))
EOF
t0=$(date +%s.%N)
if $SUDO $RUNTIME --root $WORK/state.create_timeout create \
  --timeout 200ms -b "$BUNDLE" ctimeout 2>/dev/null; then
  check "create timeout rejects runaway hook" "false"
else
  t1=$(date +%s.%N)
  check "create timeout rejects runaway hook" \
    "python3 -c 'import sys; sys.exit(0 if $t1 - $t0 < 5 else 1)'"
fi

write_config start_timeout "" '"/bin/sleep", "30"'
python3 - <<EOF
import json
p = "$BUNDLE/config.json"
c = json.load(open(p))
c["hooks"] = {"poststart": [{
  "path": "/usr/bin/sleep",
  "args": ["sleep", "30"]
}]}
json.dump(c, open(p, "w"))
EOF
$SUDO $RUNTIME --root $WORK/state.start_timeout create -b "$BUNDLE" cstart
t0=$(date +%s.%N)
$SUDO $RUNTIME --root $WORK/state.start_timeout start --timeout 200ms cstart
t1=$(date +%s.%N)
check "start timeout bounds runaway poststart hook" \
  "python3 -c 'import sys; sys.exit(0 if $t1 - $t0 < 5 else 1)'"
$SUDO $RUNTIME --root $WORK/state.start_timeout delete -f cstart

write_config delete_timeout "" '"/bin/sleep", "30"'
python3 - <<EOF
import json
p = "$BUNDLE/config.json"
c = json.load(open(p))
c["hooks"] = {"poststop": [{
  "path": "/usr/bin/sleep",
  "args": ["sleep", "30"]
}]}
json.dump(c, open(p, "w"))
EOF
$SUDO $RUNTIME --root $WORK/state.delete_timeout create -b "$BUNDLE" cdelete
$SUDO $RUNTIME --root $WORK/state.delete_timeout start cdelete
t0=$(date +%s.%N)
$SUDO $RUNTIME --root $WORK/state.delete_timeout delete --timeout 200ms -f cdelete
t1=$(date +%s.%N)
check "delete timeout bounds runaway poststop hook" \
  "python3 -c 'import sys; sys.exit(0 if $t1 - $t0 < 5 else 1)'"

# ── 3. process.scheduler ────────────────────────────────────────────────
echo "== 3. process.scheduler =="
write_config sched ',
    "scheduler": {"policy": "SCHED_BATCH", "nice": 7}
  ' '"/bin/sleep", "30"'
$SUDO $RUNTIME --root $WORK/state.sched create -b "$BUNDLE" c3
$SUDO $RUNTIME --root $WORK/state.sched start c3
sleep 0.2
PID=$($SUDO cat $WORK/state.sched/c3/init.pid)
if [[ ! -e /proc/$PID/stat ]]; then
  echo "  workload init pid $PID is gone — child.err follows:" >&2
  $SUDO cat "$WORK/state.sched/c3/child.err" 2>&1 || true
  fail=$((fail + 2))
else
  policy=$($SUDO awk '{print $41}' /proc/$PID/stat)
  nice=$($SUDO awk '{print $19}' /proc/$PID/stat)
  check "policy is SCHED_BATCH (3)" "[[ $policy == 3 ]]"
  check "nice is 7"                 "[[ $nice == 7 ]]"
fi
agent_json=$WORK/agent-exec.json
$SUDO $RUNTIME --root $WORK/state.sched exec \
  --timeout 2s --kill-tree --max-output-bytes 5 --json \
  c3 -- /bin/sh -c 'printf stdout-long; printf stderr-long >&2' > "$agent_json"
check "agent exec captures stdout/stderr with truncation" \
  "python3 -c 'import json,sys; j=json.load(open(\"$agent_json\")); sys.exit(0 if j[\"exit_code\"] == 0 and j[\"stdout\"] == \"stdou\" and j[\"stderr\"] == \"stder\" and j[\"stdout_truncated\"] and j[\"stderr_truncated\"] else 1)'"
timeout_json=$WORK/agent-timeout.json
$SUDO $RUNTIME --root $WORK/state.sched exec \
  --timeout 200ms --kill-tree --json \
  c3 -- /bin/sh -c 'sleep 5' > "$timeout_json"
check "agent exec reports timeout" \
  "python3 -c 'import json,sys; j=json.load(open(\"$timeout_json\")); sys.exit(0 if j[\"timeout\"] is True and j[\"duration_ms\"] < 5000 else 1)'"
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
