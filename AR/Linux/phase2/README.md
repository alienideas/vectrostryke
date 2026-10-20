# Phase 2 — AR Linux agent (contract-compliant)

**One OS (Linux)** end-to-end path:

**Collect → Decision Core (Phase 1) → Act → Evidence (Phase 0 contracts)**

## Run scenarios

```bash
cd AR/Linux/phase2
python3 agent/agent.py scenario lolbin
python3 agent/agent.py scenario ransomware_prep
python3 agent/agent.py scenario benign_health
python3 agent/agent.py scenario deception
python3 agent/agent.py live
```

## Tests

```bash
python3 tests/test_phase2_e2e.py
```

## Layout

- `agent/collect.py` — Events (scenarios + light live snapshot)
- `agent/act.py` — Safe Linux actions (logical isolate, quarantine dir, alert log)
- `agent/agent.py` — Orchestration + pack load / LKG
- `data/packs/` — policy pack
- `data/evidence/` — written Evidence JSON
- `data/quarantine/` — quarantine markers/files

© VectorStryke
