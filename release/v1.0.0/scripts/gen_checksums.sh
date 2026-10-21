#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/release/v1.0.0/checksums/SHA256SUMS"
cd "$ROOT"
find AS platform/shared platform/decision_core AR/Linux/phase2 AR/Linux/phase3 \
  -type f \( -name '*.py' -o -name '*.json' \) ! -path '*/__pycache__/*' \
  | sort | xargs sha256sum > "$OUT"
echo "Wrote $OUT"
wc -l "$OUT"
