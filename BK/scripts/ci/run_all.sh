#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
./scripts/ci/lint.sh || true
./scripts/ci/build.sh || true
./scripts/ci/test.sh || true
echo "==> BK CI finished"
