#!/usr/bin/env bash
# Install the repo's git hooks. Run once per clone:
#   bash scripts/install-hooks.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

# Prefer the user-friendly approach: point core.hooksPath at our
# tracked directory. Survives `git clean`, no symlink dance, and the
# user can opt out with `git config --unset core.hooksPath`.
git -C "$ROOT" config core.hooksPath scripts/git-hooks
mkdir -p "$ROOT/scripts/git-hooks"
chmod +x "$ROOT/scripts/pre-commit"
ln -sf ../pre-commit "$ROOT/scripts/git-hooks/pre-commit"

echo "installed: pre-commit (cargo fmt check)"
echo "uninstall: git config --unset core.hooksPath"
