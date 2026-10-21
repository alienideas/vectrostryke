# VectorStryke on Windows

## ASG (Anti-Spam)

```powershell
cd AS\windows
.\Start-ASG.ps1 -Port 8787
# Optional: .\Install-ASG-Task.ps1
.\Test-ASG.ps1
```

Requires **Python 3.10+** on PATH.

## AR

```powershell
cd AR\Windows
.\VectorStryke.ps1
```

## AV

```powershell
cd AV\windows
# See VectorStrykeAV / Core modules
```

## Platform tests

```powershell
python platform\phase11\tests\test_phase11.py
python AS\tests\test_asg.py
```
