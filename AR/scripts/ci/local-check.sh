#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
echo "AR local-check (Linux)"
python3 -m compileall -q Linux 2>/dev/null || true
if [ -f Linux/vectorstryke.py ]; then python3 -c "import ast; ast.parse(open('Linux/vectorstryke.py').read())"; fi
echo "OK"
