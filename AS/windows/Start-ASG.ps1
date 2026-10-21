param(
  [string]$Config = "",
  [string]$Root = "",
  [string]$HostAddr = "127.0.0.1",
  [int]$Port = 8787
)
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$AsRoot = Resolve-Path (Join-Path $Here "..")
if (-not $Root) { $Root = $AsRoot.Path }
if (-not $Config) { $Config = Join-Path $Root "config\asg.json" }
$Server = Join-Path $Root "linux\asg\adapters\http_server.py"
$env:PYTHONPATH = (Join-Path $Root "linux")
Write-Host "Starting ASG on ${HostAddr}:${Port}"
python $Server --config $Config --root $Root --host $HostAddr --port $Port
