# Team access — vectrostryke

**Repository:** https://github.com/alienideas/vectrostryke  
**Visibility:** Public

## Clone

```bash
git clone https://github.com/alienideas/vectrostryke.git
cd vectrostryke
```

## Status of this import

This repo was created from the VectorStryke Grok project workspace and seeded via the GitHub API.

- **Present:** README, VERSION, CONTRIBUTING, platform stubs, ASG core (config, models, scoring, geo, protocol, RBL, rate), release notes pointers.
- **May still be incomplete vs full local tree:** full `platform/phase4–11`, full `AR/Windows` modules, `AV`/`BK`/`Core` full sources, PDFs, large data.

If you need the **complete** local tree immediately, sync from the project Drive/SharePoint `artifacts` folder or ask the maintainer to finish bulk push / `git push` from a machine with the full checkout.

## Python tests (when sources present)

```bash
python3 platform/shared/contracts/tests/test_contracts.py
python3 AS/tests/test_asg.py
```

© VectorStryke
