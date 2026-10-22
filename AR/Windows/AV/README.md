# VectorStryke AV – Object-Oriented PowerShell Antivirus

Modern, modular, **pure PowerShell** antivirus-style scanner for **Windows 10 / 11 and Windows Server**.  
Built exclusively with classes and .NET types that ship with the OS (no NuGet, no third-party DLLs).

## Design goals (Agile-ready)

| Goal | How it is achieved |
|------|--------------------|
| Object-oriented | PowerShell classes with single responsibility |
| Extensible | Drop a new `*Stage.ps1` into `Modules\` – auto-discovered |
| Testable | Each stage + Scorer can be unit-tested with Pester |
| Parallel | Runspace pool (configurable thread count) |
| Safe remediation | AES-256 quarantine + JSON-L manifest, no blind deletes of system paths |
| OOB | Works on any Windows 10+ / Server with PowerShell 5.1+ |

## Folder layout

```
AV/
├── Start-VectorStrykeAV.ps1
├── Core/
│   ├── FileInfo.ps1, Config.ps1, RunContext.ps1, PipelineBase.ps1
│   ├── Scorer.ps1, Scheduler.ps1, QuarantineManager.ps1
│   ├── Reporter.ps1, Orchestrator.ps1
├── Modules/
│   ├── HashStage.ps1, SignatureStage.ps1, EntropyStage.ps1
│   ├── MLScoreStage.ps1, RemoteReputationStage.ps1
│   └── CustomStageSample.ps1
└── README.md
```

## Quick start

```powershell
cd path\to\AR\Windows\AV
.\Start-VectorStrykeAV.ps1 -Mode QuickScan -Threads 4
.\Start-VectorStrykeAV.ps1 -Mode FullScan -Threads 4
.\Start-VectorStrykeAV.ps1 -Mode QuickScan -Quiet
```

Reports: `%ProgramData%\VectorStryke\AV\Reports`  
Quarantine: `%ProgramData%\VectorStryke\AV\Quarantine`

## Scoring (Bayesian posterior)

| Posterior | Classification | Action |
|-----------|----------------|--------|
| ≤ 0.20 | Clean | Log only |
| 0.20–0.60 | Quarantine | Encrypt + review UI |
| > 0.60 | Malicious | Auto-quarantine |

## Optional VirusTotal

```powershell
$env:VS_VT_APIKEY = 'your-virustotal-key'
```

## Relation to the main agent

This AV scanner is complementary, on-demand. The primary agent (`..\VectorStryke.ps1`) focuses on continuous anti-ransomware behavioural monitoring, canaries, OS-security detection and recovery.
