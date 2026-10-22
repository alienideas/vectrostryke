# VectorStryke AR — Anti-Ransomware Module

Cross-platform anti-ransomware agents (Sense–Decide–Act).

## Layout

| Path | Platform |
|------|----------|
| `Linux/` | Python `vs_core` + `vectorstryke.py` |
| `Windows/` | PowerShell modules + `VectorStryke.ps1` |
| `Unix/` | POSIX sh agent |
| `macOS/` | launchd shim |

## Quick start

```bash
# Linux
cd Linux && python3 vectorstryke.py install && python3 vectorstryke.py status

# Windows
cd Windows
.\VectorStryke.ps1 install
.\VectorStryke.ps1 status
```

Response modes: **Automatic** (no approvals) | **Manual** (approvals; timeout never auto-acts).
