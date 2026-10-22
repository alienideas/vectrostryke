# Platform structure

Monorepo layout for VectorStryke universal security:

- `modules/` — AR, AV, BK, AS, Core (pointers + mirrored sources)
- `shared/contracts` — Event/Action/PolicyPack/Evidence schemas
- `shared/policy-packs` — signed policy examples
- `phase0`–`phase11` — contract-first implementation slices
- `docs/` — architecture, algorithms, attack vectors
- `deploy/` — packaging notes

Live product modules also exist at repo root: `AR/`, `AV/`, `BK/`, `AS/`, `Core/`.
