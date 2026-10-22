# VectorStryke — High-Level Architecture & Algorithm

**© VectorStryke**

## Sense → Decide → Act

1. **Sense** — host telemetry, canaries, OS-SEC signals, mail/network (AS)
2. **Decide** — Decision Core + signed PolicyPacks (offline-first)
3. **Act** — quarantine, approve queue, recovery checkpoints, backup (BK)

## Modules

AR (anti-ransomware), AV (on-demand scan), BK (backup), AS (anti-spam), Core (engine).

## Cross-platform

Windows PowerShell, Linux Python, Unix sh, macOS shims. Contracts in `platform/shared/contracts`.

Full developer specification: local `VS_Algorithm_Developer_Specification.md` / PDFs under `platform/docs/`.
