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

# ── 5. overlayfs quick reset ───────────────────────────────────────────
echo "== 5. overlayfs quick reset =="
echo lower > "$BUNDLE/rootfs/existing"
echo remove > "$BUNDLE/rootfs/remove_me"
chmod 666 "$BUNDLE/rootfs/existing" "$BUNDLE/rootfs/remove_me"
write_config reset "" '"/bin/sh", "-c", "echo changed >/existing; rm /remove_me; echo added >/added; echo secret >/root_token"'
python3 - <<EOF
import json
p = "$BUNDLE/config.json"
c = json.load(open(p))
c["rsrun"] = {"rootfs": {"backend": "overlayfs"}}
json.dump(c, open(p, "w"))
EOF
$SUDO $RUNTIME --root $WORK/state.reset create -b "$BUNDLE" c5
$SUDO $RUNTIME --root $WORK/state.reset start c5
for _ in $(seq 1 100); do
  status=$($SUDO $RUNTIME --root $WORK/state.reset state c5)
  if echo "$status" | grep -q '"status":"stopped"'; then
    break
  fi
  sleep 0.05
done
check "container wrote marker through overlay" \
  "$SUDO test -f $WORK/state.reset/c5/overlay/merged/added"
check "lower rootfs stayed clean" \
  "grep -q '^lower$' $BUNDLE/rootfs/existing && test -e $BUNDLE/rootfs/remove_me && test ! -e $BUNDLE/rootfs/added"
changed_json=$WORK/changed-files.json
$SUDO $RUNTIME --root $WORK/state.reset changed-files --json c5 > "$changed_json"
check "changed-files reports add/modify/delete" \
  "python3 -c 'import json,sys; j=json.load(open(\"$changed_json\")); m={f[\"path\"]: f[\"kind\"] for f in j[\"files\"]}; sys.exit(0 if m.get(\"added\") == \"added\" and m.get(\"existing\") == \"modified\" and m.get(\"remove_me\") == \"deleted\" else 1)'"
diff_json=$WORK/diff.json
$SUDO $RUNTIME --root $WORK/state.reset diff --json c5 > "$diff_json"
check "diff reports size delta and sensitive paths" \
  "python3 -c 'import json,sys; fs=json.load(open(\"$diff_json\"))[\"files\"]; by={f[\"path\"]: f for f in fs}; sys.exit(0 if by[\"existing\"][\"size_delta\"] != 0 and by[\"root_token\"][\"sensitive\"] is True else 1)'"
$SUDO $RUNTIME --root $WORK/state.reset mark c5 step_0
effects_empty_json=$WORK/effects-empty.json
$SUDO $RUNTIME --root $WORK/state.reset effects --since step_0 --json c5 > "$effects_empty_json"
check "effects is empty immediately after marker" \
  "python3 -c 'import json,sys; j=json.load(open(\"$effects_empty_json\")); sys.exit(0 if j[\"persistent_fs_change\"] is False and j[\"changed_files\"] == [] else 1)'"
echo after-marker | $SUDO tee "$WORK/state.reset/c5/overlay/merged/after_marker" >/dev/null
echo changed-again | $SUDO tee "$WORK/state.reset/c5/overlay/merged/existing" >/dev/null
effects_json=$WORK/effects.json
$SUDO $RUNTIME --root $WORK/state.reset effects --since step_0 --json c5 > "$effects_json"
check "effects reports filesystem changes since marker" \
  "python3 -c 'import json,sys; j=json.load(open(\"$effects_json\")); changed=set(j[\"changed_files\"]); sys.exit(0 if j[\"persistent_fs_change\"] is True and {\"after_marker\", \"existing\"} <= changed and j[\"bytes_written\"] > 0 else 1)'"
diff_tar=$WORK/diff.tar
$SUDO $RUNTIME --root $WORK/state.reset export-diff --format tar c5 > "$diff_tar"
tar -tf "$diff_tar" > "$WORK/diff.tar.list"
check "export-diff tar includes changes and whiteout" \
  "grep -q '^added$' $WORK/diff.tar.list && grep -q '^existing$' $WORK/diff.tar.list && grep -q '^.wh.remove_me$' $WORK/diff.tar.list"
$SUDO $RUNTIME --root $WORK/state.reset snapshot c5 snap1
restore_json=$WORK/restore.json
$SUDO $RUNTIME --root $WORK/state.reset restore --json snap1 c6 > "$restore_json"
check "restore materializes snapshot as stopped overlay state" \
  "python3 -c 'import json,sys; j=json.load(open(\"$restore_json\")); sys.exit(0 if j[\"restored\"] is True and j[\"backend\"] == \"overlayfs\" else 1)' && $SUDO grep -q '^changed-again$' $WORK/state.reset/c6/overlay/merged/existing && $SUDO test ! -e $WORK/state.reset/c6/overlay/merged/remove_me"
fork_json=$WORK/fork.json
$SUDO $RUNTIME --root $WORK/state.reset fork --json c5 c7 > "$fork_json"
check "fork clones current upperdir into independent stopped state" \
  "python3 -c 'import json,sys; j=json.load(open(\"$fork_json\")); sys.exit(0 if j[\"forked\"] is True and j[\"backend\"] == \"overlayfs\" else 1)' && $SUDO grep -q '^added$' $WORK/state.reset/c7/overlay/merged/added"
echo fork-only | $SUDO tee "$WORK/state.reset/c7/overlay/merged/fork_only" >/dev/null
check "fork does not share writable state with source" \
  "$SUDO test -e $WORK/state.reset/c7/overlay/merged/fork_only && $SUDO test ! -e $WORK/state.reset/c5/overlay/merged/fork_only"
checkpoint_json=$WORK/checkpoint.json
$SUDO $RUNTIME --root $WORK/state.reset checkpoint --json --pack overlay2 c5 cp1 > "$checkpoint_json"
check "checkpoint records immutable overlay2 lower layer chain" \
  "python3 -c 'import json,sys; j=json.load(open(\"$checkpoint_json\")); sys.exit(0 if j[\"checkpointed\"] is True and j[\"backend\"] == \"overlayfs\" and j[\"pack\"] == \"overlay2\" and len(j[\"lowerdirs\"]) >= 2 else 1)' && $SUDO test -d $WORK/state.reset/.layers/l"
fork_cp_a_json=$WORK/fork-checkpoint-a.json
fork_cp_b_json=$WORK/fork-checkpoint-b.json
$SUDO $RUNTIME --root $WORK/state.reset fork-checkpoint --json cp1 c8 > "$fork_cp_a_json"
$SUDO $RUNTIME --root $WORK/state.reset fork-checkpoint --json cp1 c9 > "$fork_cp_b_json"
check "fork-checkpoint starts branches with empty writable uppers" \
  "python3 -c 'import json,sys; a=json.load(open(\"$fork_cp_a_json\")); b=json.load(open(\"$fork_cp_b_json\")); sys.exit(0 if a[\"forked\"] is True and b[\"forked\"] is True and len(a[\"lowerdirs\"]) >= 2 and len(b[\"lowerdirs\"]) >= 2 else 1)' && [[ $($SUDO find $WORK/state.reset/c8/overlay/upper -mindepth 1 | wc -l) -eq 0 ]] && [[ $($SUDO find $WORK/state.reset/c9/overlay/upper -mindepth 1 | wc -l) -eq 0 ]]"
echo checkpoint-branch | $SUDO tee "$WORK/state.reset/c8/overlay/merged/checkpoint_branch" >/dev/null
check "fork-checkpoint branches do not share writable state" \
  "$SUDO test -e $WORK/state.reset/c8/overlay/merged/checkpoint_branch && $SUDO test ! -e $WORK/state.reset/c9/overlay/merged/checkpoint_branch && $SUDO test ! -e $WORK/state.reset/.checkpoints/cp1/layer/checkpoint_branch"
checkpoint2_json=$WORK/checkpoint2.json
$SUDO $RUNTIME --root $WORK/state.reset checkpoint --json --pack overlay2 c8 cp2 > "$checkpoint2_json"
fork_cp2_json=$WORK/fork-checkpoint-c.json
$SUDO $RUNTIME --root $WORK/state.reset fork-checkpoint --json cp2 c10 > "$fork_cp2_json"
check "fork-checkpoint supports multiple lowerdirs" \
  "python3 -c 'import json,sys; cp=json.load(open(\"$checkpoint2_json\")); f=json.load(open(\"$fork_cp2_json\")); sys.exit(0 if cp[\"checkpointed\"] is True and len(cp[\"lowerdirs\"]) >= 3 and f[\"forked\"] is True and len(f[\"lowerdirs\"]) >= 3 else 1)' && $SUDO test -f $WORK/state.reset/c10/overlay/merged/checkpoint_branch && $SUDO test -f $WORK/state.reset/c10/overlay/merged/added && [[ $($SUDO find $WORK/state.reset/c10/overlay/upper -mindepth 1 | wc -l) -eq 0 ]]"
echo nested-branch | $SUDO tee "$WORK/state.reset/c10/overlay/merged/nested_branch" >/dev/null
check "multi-lowerdir branch writes stay in newest upper" \
  "$SUDO test -e $WORK/state.reset/c10/overlay/upper/nested_branch && $SUDO test ! -e $WORK/state.reset/.checkpoints/cp2/layer/nested_branch && $SUDO test ! -e $WORK/state.reset/c8/overlay/merged/nested_branch"
portable_tar=$WORK/portable-cp2.tar
$SUDO $RUNTIME --root $WORK/state.reset export-checkpoint cp2 > "$portable_tar"
$SUDO $RUNTIME --root $WORK/state.reset import-checkpoint --json cp2-portable "$portable_tar" > "$WORK/import-checkpoint.json"
$SUDO $RUNTIME --root $WORK/state.reset fork-checkpoint --json cp2-portable c11 > "$WORK/fork-checkpoint-portable.json"
write_config activate-portable "" '"/bin/sh", "-c", "sleep 60"'
$SUDO $RUNTIME --root $WORK/state.reset activate --json --bundle "$BUNDLE" c11 > "$WORK/activate-portable.json"
check "portable overlay2 checkpoint imports, forks, and activates" \
  "python3 -c 'import json,sys; i=json.load(open(\"$WORK/import-checkpoint.json\")); f=json.load(open(\"$WORK/fork-checkpoint-portable.json\")); a=json.load(open(\"$WORK/activate-portable.json\")); sys.exit(0 if i[\"imported\"] is True and f[\"forked\"] is True and a[\"activated\"] is True else 1)' && $SUDO $RUNTIME --root $WORK/state.reset state c11 | grep -q '\"status\":\"created\"'"
$SUDO $RUNTIME --root $WORK/state.reset start c11
$SUDO $RUNTIME --root $WORK/state.reset exec --json c11 -- sh -c 'test -f /added && test -f /checkpoint_branch && echo portable-branch-ok' > "$WORK/portable-exec.json"
check "activated portable branch supports rollout exec" \
  "python3 -c 'import json,sys; j=json.load(open(\"$WORK/portable-exec.json\")); sys.exit(0 if j[\"exit_code\"] == 0 and \"portable-branch-ok\" in j[\"stdout\"] else 1)'"
$SUDO $RUNTIME --root $WORK/state.reset delete -f c6
$SUDO $RUNTIME --root $WORK/state.reset delete -f c7
$SUDO $RUNTIME --root $WORK/state.reset delete -f c8
$SUDO $RUNTIME --root $WORK/state.reset delete -f c9
$SUDO $RUNTIME --root $WORK/state.reset delete -f c10
$SUDO $RUNTIME --root $WORK/state.reset delete -f c11
reset_json=$WORK/reset.json
$SUDO $RUNTIME --root $WORK/state.reset reset --json c5 > "$reset_json"
check "reset reports overlayfs backend" \
  "python3 -c 'import json,sys; j=json.load(open(\"$reset_json\")); sys.exit(0 if j[\"backend\"] == \"overlayfs\" and j[\"reset\"] is True and j[\"resetCount\"] == 1 else 1)'"
check "reset removed marker from merged rootfs" \
  "$SUDO test ! -e $WORK/state.reset/c5/overlay/merged/added && $SUDO test -e $WORK/state.reset/c5/overlay/merged/remove_me"
$SUDO $RUNTIME --root $WORK/state.reset delete -f c5

# ── 6. cleanup ─────────────────────────────────────────────────────────
$SUDO rm -rf "$WORK"

echo
echo "smoke: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
