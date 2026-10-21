$ErrorActionPreference = "Stop"
$AsRoot = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")
$env:PYTHONPATH = Join-Path $AsRoot "linux"
python (Join-Path $AsRoot "tests\test_asg.py")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "ASG Windows test path OK"
