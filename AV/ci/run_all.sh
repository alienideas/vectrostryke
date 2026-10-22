#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
./lint_linux.sh
./lint_unix.sh
echo 'AV CI done'
