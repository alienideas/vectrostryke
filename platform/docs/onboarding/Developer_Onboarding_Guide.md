# Developer Onboarding — VectorStryke

**© VectorStryke**

## Repo map

| Path | Purpose |
|------|---------|
| `AR/` | Anti-ransomware agents |
| `AV/` | On-demand antivirus |
| `BK/` | Backup complementary agent |
| `AS/` | Anti-spam gateway |
| `Core/` | Detection engine |
| `platform/` | Contracts, phases, design docs |
| `release/v1.0.0/` | Packaging |

## First steps

1. Clone `https://github.com/alienideas/vectrostryke`
2. Read `platform/shared/contracts` schemas
3. Run module CI scripts under each module
4. Prefer PRs with `make ci` / `scripts/ci/run_all.sh` green

## PDFs

Formal PDF specifications live under `*/docs/*.pdf` in the authoring workspace. Binary PDFs should be added with **Git LFS** or release assets; markdown/dot sources are the review source of truth on GitHub.
