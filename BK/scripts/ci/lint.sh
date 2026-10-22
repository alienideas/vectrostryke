#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if command -v golangci-lint >/dev/null 2>&1; then
  golangci-lint run ./... || true
else
  echo "lint placeholder — install golangci-lint for full checks"
fi
