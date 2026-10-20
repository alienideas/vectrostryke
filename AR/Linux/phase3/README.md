# Phase 3 — Operator Surface (offline)

Human control plane **without** a central server:

- List **pending** approvals  
- **Approve** / **deny**  
- View **evidence**  
- **Status** for local dashboard  

## CLI

```bash
cd AR/Linux/phase3

python3 operator/cli.py scenario ransomware_prep
python3 operator/cli.py pending
python3 operator/cli.py approve <pending_id>
python3 operator/cli.py deny <pending_id>
python3 operator/cli.py evidence
python3 operator/cli.py status
python3 operator/cli.py export-status
```

Open `static/dashboard.html` (after export-status) in a browser.

## Tests

```bash
python3 tests/test_phase3_operator.py
```

© VectorStryke
