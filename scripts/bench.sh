#!/bin/bash
# Build the bench bundle (minimal /bin/true container) and run hyperfine
# of `create + start + delete` against rsrun and any other runtimes
# present on PATH. Linux-only; runs in Lima for macOS hosts.
#
# Usage:
#   scripts/bench.sh                  # rsrun only
#   scripts/bench.sh crun youki runc  # comparison set
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUNDLE=/tmp/rsrun-bench-bundle
RT_RSRUN="$ROOT/target/release/rsrun"

if [[ ! -x $RT_RSRUN ]]; then
  echo "build rsrun first: cargo build --release" >&2
  exit 1
fi

# Bundle: rootfs from system busybox (relative-symlink applets), config
# runs /bin/true with minimal namespaces.
build_bundle() {
  if [[ -f $BUNDLE/config.json && -x $BUNDLE/rootfs/bin/sh ]]; then
    return
  fi
  rm -rf "$BUNDLE"
  mkdir -p "$BUNDLE/rootfs/bin"
  cp -L /usr/bin/busybox "$BUNDLE/rootfs/bin/busybox"
  for app in $("$BUNDLE/rootfs/bin/busybox" --list); do
    [[ $app == busybox ]] && continue
    ln -sf busybox "$BUNDLE/rootfs/bin/$app"
  done
  cat > "$BUNDLE/config.json" <<'JSON'
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["true"],
    "env": ["PATH=/bin"],
    "cwd": "/",
    "capabilities": {
      "bounding":  ["CAP_AUDIT_WRITE"],
      "effective": ["CAP_AUDIT_WRITE"],
      "permitted": ["CAP_AUDIT_WRITE"]
    }
  },
  "root": {"path": "rootfs"},
  "hostname": "b",
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
     "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
    {"destination": "/sys", "type": "sysfs", "source": "sysfs",
     "options": ["nosuid", "noexec", "nodev", "ro"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"}, {"type": "network"}, {"type": "ipc"},
      {"type": "uts"}, {"type": "mount"}
    ]
  }
}
JSON
}

run_bench() {
  local name=$1 rt=$2
  local stderr=/tmp/rsrun-bench.$name.stderr
  echo "=== $name ($rt) ==="
  sudo rm -rf "/run/bench-$name" 2>/dev/null || true
  sudo hyperfine \
    --warmup 30 --min-runs 200 \
    --prepare "sudo sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null; \
               sudo rm -rf /run/bench-$name/b 2>/dev/null || true" \
    "$rt --root /run/bench-$name create -b $BUNDLE b && \
     $rt --root /run/bench-$name start b && \
     $rt --root /run/bench-$name delete -f b" \
    2> "$stderr" \
    | grep -E "^  Time|^  Range" || cat "$stderr"
  echo
}

build_bundle

run_bench rsrun "$RT_RSRUN"
for other in "$@"; do
  if command -v "$other" >/dev/null 2>&1; then
    run_bench "$other" "$(command -v "$other")"
  else
    echo "(skip: $other not on PATH)"
  fi
done
