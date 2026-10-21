param(
  [string]$Python = "python",
  [string]$TaskName = "VectorStryke-ASG",
  [int]$Port = 8787
)
$AsRoot = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")
$Server = Join-Path $AsRoot "linux\asg\adapters\http_server.py"
$Config = Join-Path $AsRoot "config\asg.json"
$Action = New-ScheduledTaskAction -Execute $Python -Argument "`"$Server`" --config `"$Config`" --root `"$AsRoot`" --host 127.0.0.1 --port $Port" -WorkingDirectory $AsRoot
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force
Write-Host "Registered task $TaskName"
