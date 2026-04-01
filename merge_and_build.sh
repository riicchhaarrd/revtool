#!/usr/bin/env bash
# Merge origin/master into the current wasm branch, then build WASM.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Fetching origin..."
git fetch origin

echo "==> Merging origin/master into $(git branch --show-current)..."
git merge origin/master

echo "==> Building WASM..."
"$SCRIPT_DIR/build_wasm.sh" "$@"
