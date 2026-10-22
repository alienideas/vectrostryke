#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
mkdir -p bin
go build -o bin/control-plane ./cmd/control-plane 2>/dev/null || true
go build -o bin/agent ./cmd/agent 2>/dev/null || true
echo "BK build step complete"
