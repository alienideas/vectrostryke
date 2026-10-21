#!/usr/bin/env bash
# VectorStryke v1.0.0 Linux installer (reference)
set -euo pipefail
PREFIX="${PREFIX:-/opt/vectorstryke}"
ETC="${ETC:-/etc/vectorstryke}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

echo "Installing VectorStryke 1.0.0 to $PREFIX"
sudo mkdir -p "$PREFIX" "$ETC" /var/log/vectorstryke
sudo id vectorstryke 2>/dev/null || sudo useradd -r -s /usr/sbin/nologin vectorstryke

sudo rsync -a --exclude '.git' --exclude '**/__pycache__' --exclude '**/build' \
  "$ROOT/AS" "$ROOT/AR" "$ROOT/platform" "$ROOT/AV" "$ROOT/BK" "$ROOT/Core" \
  "$ROOT/VERSION" "$ROOT/release" \
  "$PREFIX/"

sudo cp "$ROOT/release/v1.0.0/configs/asg.production.json" "$ETC/"
sudo cp "$ROOT/release/v1.0.0/configs/platform.production.env" "$ETC/"
sudo cp "$ROOT/release/v1.0.0/systemd/vectorstryke-asg.service" /etc/systemd/system/ 2>/dev/null || true

if [[ ! -f "$ETC/keys/pack.key" ]]; then
  sudo mkdir -p "$ETC/keys"
  sudo python3 -c "import os; open('/etc/vectorstryke/keys/pack.key','wb').write(os.urandom(32))"
  sudo chmod 600 "$ETC/keys/pack.key"
  echo "Generated $ETC/keys/pack.key — back up offline"
fi

sudo chown -R vectorstryke:vectorstryke "$PREFIX" /var/log/vectorstryke
echo "Install complete. Enable ASG with:"
echo "  sudo systemctl daemon-reload && sudo systemctl enable --now vectorstryke-asg"
echo "  curl -s http://127.0.0.1:8787/health"
