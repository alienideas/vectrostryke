#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('FullScan','QuickScan','UpdateIndex')]
    [string]$Mode = 'QuickScan',
    [ValidateRange(1, 16)]
    [int]$Threads = 2,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$script:VSQuiet = [bool]$Quiet
$Root = $PSScriptRoot

$coreFiles = @(
    'FileInfo.ps1',
    'Config.ps1',
    'RunContext.ps1',
    'PipelineBase.ps1',
    'Scorer.ps1',
    'Scheduler.ps1',
    'QuarantineManager.ps1',
    'Reporter.ps1',
    'Orchestrator.ps1'
)
foreach ($f in $coreFiles) {
    $path = Join-Path $Root "Core\$f"
    if (Test-Path $path) { . $path }
    else { Write-Error "Missing core file: $path"; return }
}

Get-ChildItem (Join-Path $Root 'Modules') -Filter '*Stage.ps1' -ErrorAction SilentlyContinue |
    ForEach-Object { . $_.FullName }

$cfg  = [VSConfig]::new()
$opts = [VSOptions]::new()
$opts.Mode    = $Mode
$opts.Threads = $Threads
$opts.Quiet   = [bool]$Quiet

$ctx  = [VSRunContext]::new($cfg, $opts)
$orch = [VSOrchestrator]::new($ctx, $Root)

try {
    $orch.Run()
} catch {
    if (Get-Command Write-VSLog -ErrorAction SilentlyContinue) {
        Write-VSLog "FATAL: $_" 'Error'
    }
    throw
} finally {
    $ctx.Cleanup()
}

Write-Host ""
Write-Host "VectorStryke AV finished. Reports under: $($cfg.ReportPath)" -ForegroundColor Cyan
if (-not $Quiet) {
    Write-Host "Counters: Scanned=$($ctx.Counters.FilesScanned) Quarantined=$($ctx.Counters.FilesQuarantined) Errors=$($ctx.Counters.Errors)"
}
