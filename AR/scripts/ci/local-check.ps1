# AR Windows local smoke
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Write-Host "AR local-check (Windows) root=$root"
$mod = Join-Path $root 'Windows/Modules'
if (Test-Path $mod) {
  Get-ChildItem $mod -Filter '*.ps1' | ForEach-Object { Write-Host "  module $($_.Name)" }
}
Write-Host 'OK'
