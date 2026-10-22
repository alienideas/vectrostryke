#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pytest tests -q 2>/dev/null || python3 tests/test_contracts.py
echo contracts OK
