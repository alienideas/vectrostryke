# Windows & macOS support added

- Cross-platform hostname (`socket.gethostname`) in AS bridge, AR phase2, phase8 adapters
- `platform/shared/compat/hostinfo.py`
- AS Windows: `Start-ASG.ps1`, `Install-ASG-Task.ps1`, `Test-ASG.ps1`
- AS macOS: `start_asg.sh`, `com.vectorstryke.asg.plist`, `install.sh`
- AR macOS: `vectorstryke_ar.sh`
- Release docs: `release/v1.0.0/windows`, `macos`, `docs/MULTI_OS_SUPPORT.md`
