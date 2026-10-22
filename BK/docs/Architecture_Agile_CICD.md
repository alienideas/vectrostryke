# BK Architecture, Agile & CI/CD

**© VectorStryke**

Complementary backup for VectorStryke (quarantine-aware).

## Components

- `vsbk-agent` — local filesystem backup via SAL
- `vsbk-control-plane` — health HTTP
- `vsbk_core` — pipeline + SHA-256 + util

## CI

`scripts/ci/run_all.sh`: lint → build → test. GitHub Actions under `.github/workflows/`.

## Gap closure G1–G6

See `Algorithm_Gap_Closure.md` and competitiveness analysis.
