# Contributing — VectorStryke (vectrostryke)

Repo: https://github.com/alienideas/vectrostryke

## Clone

```bash
git clone https://github.com/alienideas/vectrostryke.git
cd vectrostryke
```

## Layout

- `platform/` — shared contracts, Decision Core, phases 4–11
- `AR/` `AV/` `BK/` `Core/` `AS/` — modules
- `release/v1.0.0/` — install, smoke tests, multi-OS notes

## Tests (Python 3.10+)

```bash
python3 platform/shared/contracts/tests/test_contracts.py
python3 platform/decision_core/tests/test_decision_core.py
python3 AS/tests/test_asg.py
python3 AR/Linux/phase2/tests/test_phase2_e2e.py
python3 platform/phase11/scripts/run_all_gates.py
```

## Notes

- Do not commit `*.dev.key` or production secrets.
- Prefer contract-compatible Events/Actions for new module code.

© VectorStryke
