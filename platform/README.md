# VectorStryke Platform

## Modules (canonical short names)

| Name | Path | Role |
|------|------|------|
| **AR** | `../AR/` | Anti-Ransomware |
| **AV** | `../AV/` | Antivirus |
| **BK** | `../BK/` | Backup / Recovery |
| **Core** | `../Core/` | Detection Engine |
| **AS** | `../AS/` and `modules/AS/` | Anti-Spam Gateway |

## Layout

```
platform/
├── docs/architecture|attack-vectors|algorithms|diagrams
├── modules/AR|AV|BK|Core|AS   (pointers / AS content)
├── shared/contracts|policy-packs
├── data/ ci/ control-plane/ deploy/
└── README.md STRUCTURE.md
```

Live module code sits at repository root under **AR**, **AV**, **BK**, **Core**, **AS**.

© VectorStryke
