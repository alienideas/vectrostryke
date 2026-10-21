# VectorStrykeAV

Multi-platform antivirus-style scanning module integrated with VectorStryke Decision Core.

## Layout

- `linux/vs_av/` — Python OOP pipeline (orchestrator, scorer, quarantine, reporter)
- `windows/` — PowerShell stages (Hash, Entropy, Signature, ML)
- `ci/` — lint and run scripts

## Run (Linux)

```bash
cd AV/linux
python3 -m vs_av  # or use orchestrator entry
```

© VectorStryke
