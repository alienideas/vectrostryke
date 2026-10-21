#!/usr/bin/env bash
set -euo pipefail
PREFIX="${PREFIX:-/opt/vectorstryke}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
echo "Installing VectorStryke AS to $PREFIX (macOS)"
sudo mkdir -p "$PREFIX"
sudo rsync -a "$ROOT/AS" "$ROOT/platform" "$PREFIX/"
PLIST_SRC="$HERE/com.vectorstryke.asg.plist"
sudo cp "$PLIST_SRC" /Library/LaunchDaemons/com.vectorstryke.asg.plist
echo "Load with: sudo launchctl load /Library/LaunchDaemons/com.vectorstryke.asg.plist"
echo "Health: curl -s http://127.0.0.1:8787/health"
