#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
AS_ROOT="$(cd "$HERE/.." && pwd)"
CONFIG="${1:-$AS_ROOT/config/asg.json}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8787}"
export PYTHONPATH="$AS_ROOT/linux${PYTHONPATH:+:$PYTHONPATH}"
exec python3 "$AS_ROOT/linux/asg/adapters/http_server.py" \
  --config "$CONFIG" --root "$AS_ROOT" --host "$HOST" --port "$PORT"
