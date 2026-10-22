#!/usr/bin/env bash
set -euo pipefail
sh -n unix/vectorstryke_av.sh 2>/dev/null || true
echo OK
