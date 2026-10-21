# VectorStryke Platform v1.0.0

Production-oriented release package.

## Quick start (Linux)

## Windows / macOS

- Windows: `release/v1.0.0/windows/README.md`
- macOS: `release/v1.0.0/macos/README.md`
- Matrix: `release/v1.0.0/docs/MULTI_OS_SUPPORT.md`

```bash
bash release/v1.0.0/scripts/smoke_test.sh
bash release/v1.0.0/scripts/install_linux.sh
python3 AS/linux/asg/adapters/http_server.py --config AS/config/asg.json --root AS --port 8787
curl -s http://127.0.0.1:8787/health
```

## Contents

| Path | Purpose |
|------|---------|
| `RELEASE_NOTES.md` | What shipped |
| `PRODUCTION_READINESS.md` | Go-live matrix |
| `configs/` | Production templates |
| `systemd/` | ASG service unit |
| `docker/` | Compose reference |
| `scripts/` | install, smoke, checksums |
| `docs/OPERATOR_GUIDE.md` | Day-2 ops |

## Version

See repository root `VERSION` → **1.0.0**

© VectorStryke
