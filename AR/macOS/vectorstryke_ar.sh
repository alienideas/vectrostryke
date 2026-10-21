#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
AR_ROOT="$(cd "$HERE/.." && pwd)"
ARTIFACTS="$(cd "$AR_ROOT/.." && pwd)"
export PYTHONPATH="$AR_ROOT/Linux/phase2/agent:$ARTIFACTS/platform/decision_core/src:$ARTIFACTS/platform/shared/contracts/src${PYTHONPATH:+:$PYTHONPATH}"
CMD="${1:-scenario}"
shift || true
exec python3 "$AR_ROOT/Linux/phase2/agent/agent.py" "$CMD" "$@"
