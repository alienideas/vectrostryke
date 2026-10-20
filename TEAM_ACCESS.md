# Team access — vectrostryke

**Repository:** https://github.com/alienideas/vectrostryke  
**Visibility:** Public  
**Default branch:** `main`

## Clone

```bash
git clone https://github.com/alienideas/vectrostryke.git
cd vectrostryke
```

## What is on GitHub now

### Root
README, VERSION, .gitignore, CONTRIBUTING, PLATFORM_STRUCTURE, TEAM_ACCESS

### AR
- Linux **phase2**: `agent/collect.py`, `act.py`, `agent.py`, README
- Linux **phase3**: README, PHASE3_STATUS
- macOS README

### AS
- config, models, scoring, geo, protocol auth, RBL, rate limiter
- content analyzer, rest adapter

### Platform
- contracts/decision_core status READMEs, hostinfo

## Still missing vs full local tree (~400 files)

`decision_core.py`, contract schemas/validators, phases 4–11, AR Windows/vs_core, AV/BK/Core, release packaging, many AS files (pipeline engine, http server, tests).

## Finish 100% (recommended)

On a machine with the **full** project folder:

```bash
cd /path/to/artifacts
git init && git branch -M main
git remote add origin https://github.com/alienideas/vectrostryke.git
git fetch origin
git add .
git commit -m "Complete VectorStryke tree v1.0.0"
git pull origin main --allow-unrelated-histories
git push -u origin main
```

© VectorStryke
