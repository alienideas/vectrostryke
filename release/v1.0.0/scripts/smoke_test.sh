#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
echo "== VERSION =="; cat VERSION
echo "== Gates =="; python3 platform/phase11/scripts/run_all_gates.py
echo "== ASG tests =="; python3 AS/tests/test_asg.py
echo "== ASG CLI =="; python3 AS/linux/asg_cli.py demo clean | head -5
echo "SMOKE OK"
