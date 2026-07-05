#!/usr/bin/env bash
# Start the CyberGym arvo:47101 vulnerable image through Docker using rsrun.
#
# This script is intended for Linux Docker hosts or Lima Docker VMs. It
# explicitly registers a Docker runtime entry that points at the rsrun
# binary selected by RSRUN_BIN.
#
# Examples:
#   RSRUN_BIN=/path/to/rsrun scripts/start_cybergym_test.sh
#   INTERACTIVE=1 scripts/start_cybergym_test.sh

set -euo pipefail

IMAGE=${IMAGE:-n132/arvo:47101-vul}
NAME=${NAME:-rsrun-arvo-vul}
PLATFORM=${PLATFORM:-linux/amd64}
NETWORK=${NETWORK:-none}
RUNTIME_NAME=${RUNTIME_NAME:-rsrun-test}
RSRUN_BIN=${RSRUN_BIN:-$(pwd)/target/release/rsrun}
DOCKER=${DOCKER:-docker}
DAEMON_JSON=${DAEMON_JSON:-/etc/docker/daemon.json}
SECCOMP_OPT=${SECCOMP_OPT:-seccomp=unconfined}

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  SUDO=${SUDO:-}
else
  SUDO=${SUDO:-sudo}
fi

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need "$DOCKER"
need python3

if [[ ! -x "$RSRUN_BIN" ]]; then
  echo "rsrun binary is not executable: $RSRUN_BIN" >&2
  echo "set RSRUN_BIN=/absolute/path/to/rsrun" >&2
  exit 1
fi

RSRUN_BIN=$(realpath "$RSRUN_BIN")

ensure_docker_runtime() {
  local tmp current desired
  tmp=$(mktemp)
  current=$($SUDO sh -c "cat '$DAEMON_JSON' 2>/dev/null" || printf '{}')
  desired=$(printf '%s' "$current" | python3 - "$RUNTIME_NAME" "$RSRUN_BIN" <<'PY'
import json
import sys

runtime_name = sys.argv[1]
rsrun_bin = sys.argv[2]
raw = sys.stdin.read().strip() or "{}"
try:
    data = json.loads(raw)
except json.JSONDecodeError as exc:
    raise SystemExit(f"invalid Docker daemon JSON: {exc}")

data.setdefault("runtimes", {})[runtime_name] = {"path": rsrun_bin}
print(json.dumps(data, indent=2, sort_keys=True))
PY
)
  printf '%s\n' "$desired" >"$tmp"
  if $SUDO test -f "$DAEMON_JSON" && $SUDO cmp -s "$tmp" "$DAEMON_JSON"; then
    rm -f "$tmp"
    return
  fi
  echo "registering Docker runtime '$RUNTIME_NAME' -> $RSRUN_BIN"
  $SUDO install -m 0644 "$tmp" "$DAEMON_JSON"
  rm -f "$tmp"
  if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl restart docker
  else
    $SUDO service docker restart
  fi
}

ensure_amd64_binfmt() {
  if [[ "$PLATFORM" != linux/amd64* || "$(uname -m)" == x86_64 ]]; then
    return
  fi
  if grep -Rqs "qemu-x86_64" /proc/sys/fs/binfmt_misc 2>/dev/null; then
    return
  fi
  echo "registering qemu-x86_64 binfmt for amd64 containers"
  $SUDO "$DOCKER" run --privileged --rm tonistiigi/binfmt --install amd64
}

ensure_image() {
  if $SUDO "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
    return
  fi
  echo "pulling $IMAGE for $PLATFORM"
  $SUDO "$DOCKER" pull --platform "$PLATFORM" "$IMAGE"
}

ensure_docker_runtime
ensure_amd64_binfmt
ensure_image

$SUDO "$DOCKER" rm -f "$NAME" >/dev/null 2>&1 || true

if [[ ${INTERACTIVE:-0} == 1 ]]; then
  exec $SUDO "$DOCKER" run --rm -it \
    --runtime "$RUNTIME_NAME" \
    --platform "$PLATFORM" \
    --security-opt "$SECCOMP_OPT" \
    --network "$NETWORK" \
    --entrypoint /bin/bash \
    "$IMAGE"
fi

cid=$($SUDO "$DOCKER" run -d \
  --runtime "$RUNTIME_NAME" \
  --platform "$PLATFORM" \
  --security-opt "$SECCOMP_OPT" \
  --name "$NAME" \
  --network "$NETWORK" \
  --entrypoint /bin/bash \
  "$IMAGE" \
  -lc 'uname -m; id; pwd; ls -la /src | head; echo RSRUN_START_OK; sleep infinity')

echo "started $NAME: $cid"
sleep 1
$SUDO "$DOCKER" ps --filter "name=$NAME" \
  --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Command}}'
$SUDO "$DOCKER" logs "$NAME"

cat <<EOF

Runtime registered:
  $RUNTIME_NAME -> $RSRUN_BIN

Manual inspection:
  $SUDO $DOCKER logs $NAME
  INTERACTIVE=1 RSRUN_BIN=$RSRUN_BIN $0

Cleanup:
  $SUDO $DOCKER rm -f $NAME
EOF
