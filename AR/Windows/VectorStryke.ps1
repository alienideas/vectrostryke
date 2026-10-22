#Requires -Version 5.1
<#
.SYNOPSIS
    VectorStryke - Modular Anti-Ransomware Engine for Windows
.DESCRIPTION
    Dependency-free. Modular OOP-style Modules\.
    ResponseMode: Automatic (no approvals) | Manual (approvals; timeout never auto-acts)
#>

param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "start","stop","status","scan","approve","deny","install","uninstall",
        "mode","modes","auto-on","auto-off","ossec-mode","health","ossec-status","osscan","canary-init","canary-verify",
        "checkpoint","impact-clear","update-check","update-apply","rollback",
        "lkg-save","dashboard","help"
    )]
    [string]$Command = "help",
    [string]$Id = "",
    [int]$Port = 8787,
    [switch]$Force
)

$ErrorActionPreference = "SilentlyContinue"
$Global:VectorStrykeRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$modDir = Join-Path $Global:VectorStrykeRoot "Modules"
Get-ChildItem -Path $modDir -Filter "*.ps1" -ErrorAction SilentlyContinue |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

Initialize-VSPaths

switch ($Command) {
    "start" { Start-VSEngine }
    "stop" {
        if (Test-Path $Global:VSPaths.PidFile) {
            try {
                $pidVal = [int](Get-Content $Global:VSPaths.PidFile -Raw).Trim()
                Stop-Process -Id $pidVal -Force -ErrorAction SilentlyContinue
            } catch {}
            Remove-Item $Global:VSPaths.PidFile -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped." -ForegroundColor Green
        } else {
            Write-Host "Not running." -ForegroundColor Yellow
        }
    }
    "status" { Show-VSStatus }
    "scan" {
        $cfg = Get-Config
        $snap = Invoke-VSCollect
        $findings = @(Invoke-VSDetect -Snapshot $snap -Config $cfg)
        $prelude = Test-VSEncryptionPrelude -Config $cfg -Processes $snap.processes
        if ($prelude) { $findings = @($prelude) + $findings }
        $findings | ConvertTo-Json -Depth 6
    }
    "approve" {
        if (-not $Id) { Write-Host "Usage: .\VectorStryke.ps1 approve -Id <AlertId>"; break }
        $a = Resolve-VSApproval -AlertId $Id -Decision "Approved"
        if (-not $a) { Write-Host "Alert not found"; break }
        $finding = @{}
        if ($a.Finding) {
            $a.Finding.PSObject.Properties | ForEach-Object { $finding[$_.Name] = $_.Value }
        }
        Invoke-VSAction -Finding $finding -Config (Get-Config) | Out-Null
        Write-Host "Approved and executed: $Id" -ForegroundColor Green
    }
    "deny" {
        if (-not $Id) { Write-Host "Usage: .\VectorStryke.ps1 deny -Id <AlertId>"; break }
        $a = Resolve-VSApproval -AlertId $Id -Decision "Denied"
        Write-Host $(if ($a) { "Denied" } else { "Alert not found" })
    }
    "mode" {
        $target = if ($Id) { $Id } else { "list" }
        if ($target -match '^(list|show|all)$') {
            $cfg = Get-Config
            Write-Host ("ResponseMode={0}" -f $(if ($cfg.ResponseMode) { $cfg.ResponseMode } else { "Automatic" }))
        } else {
            try {
                $cfg = Set-VSResponseMode -Mode $target
                Write-Host "ResponseMode=$($cfg.ResponseMode)" -ForegroundColor Cyan
            } catch {
                Write-Host "Usage: .\VectorStryke.ps1 mode -Id Automatic|Manual|list" -ForegroundColor Yellow
            }
        }
    }
    "modes" {
        $cfg = Get-Config
        Write-Host "=== VectorStryke modes ===" -ForegroundColor Cyan
        Write-Host ("  ResponseMode : {0}" -f $(if ($cfg.ResponseMode) { $cfg.ResponseMode } else { "Automatic" }))
        Write-Host ("  OsSecurityMode : {0}" -f $(if ($cfg.OsSecurityMode) { $cfg.OsSecurityMode } else { "Auto" }))
    }
    "ossec-mode" {
        $cfg = Get-Config
        switch -Regex ($Id) {
            '^(Auto|auto)$' {
                $cfg.OsSecurityMode = "Auto"
                Save-Config $cfg
                Write-Host "OsSecurityMode=Auto" -ForegroundColor Green
            }
            '^(Coexist|coexist)$' {
                $cfg.OsSecurityMode = "Coexist"
                $cfg.OsSecurityDetectionOnly = $true
                $cfg.OsSecurityFallbackEnabled = $false
                Save-Config $cfg
                Write-Host "OsSecurityMode=Coexist" -ForegroundColor Cyan
            }
            '^(Fallback|fallback)$' {
                $cfg.OsSecurityMode = "Fallback"
                $cfg.OsSecurityDetectionOnly = $false
                $cfg.OsSecurityFallbackEnabled = $true
                Save-Config $cfg
                Write-Host "OsSecurityMode=Fallback" -ForegroundColor Yellow
            }
            default {
                Write-Host "Usage: .\VectorStryke.ps1 ossec-mode -Id Auto|Coexist|Fallback"
            }
        }
    }
    "auto-on" {
        Set-VSResponseMode -Mode Automatic | Out-Null
        Write-Host "ResponseMode=Automatic" -ForegroundColor Green
    }
    "auto-off" {
        Set-VSResponseMode -Mode Manual | Out-Null
        Write-Host "ResponseMode=Manual" -ForegroundColor Yellow
    }
    "osscan" {
        $cfg = Get-Config
        $full = ($Id -eq "full")
        if (Get-Command Invoke-VSOsScan -ErrorAction SilentlyContinue) {
            if ($Id -eq "baseline") {
                Invoke-VSOsScan -Config $cfg -BuildBaselineOnly | ConvertTo-Json -Depth 6
            } else {
                Invoke-VSOsScan -Config $cfg -Full:$full | ConvertTo-Json -Depth 8
            }
        } else { Write-Host "OsScan module not loaded" }
    }
    "ossec-status" {
        $cfg = Get-Config
        if (Get-Command Invoke-VSOsSecurityDetect -ErrorAction SilentlyContinue) {
            Invoke-VSOsSecurityDetect -Config $cfg | ConvertTo-Json -Depth 6
        } else { Write-Host "OsSecurity module not loaded" }
    }
    "health" {
        Invoke-VSSelfHealth -Config (Get-Config) | ConvertTo-Json -Depth 5
    }
    "canary-init" {
        Initialize-VSCanaries -Config (Get-Config) | ConvertTo-Json -Depth 5
    }
    "canary-verify" {
        Test-VSCanaries | ConvertTo-Json -Depth 5
    }
    "checkpoint" {
        New-VSCheckpoint -Reason "manual" | ConvertTo-Json -Depth 5
    }
    "impact-clear" {
        $cfg = Get-Config
        if (-not $Force) {
            $v = Test-VSCanaries
            if (-not $v.ok) {
                Write-Host "Canary verify failed; use -Force to clear" -ForegroundColor Yellow
                break
            }
        }
        $cfg.ImpactPending = $false
        Save-Config $cfg
        @{ ok = $true } | ConvertTo-Json
    }
    "update-check" {
        Invoke-VSUpdateCheck -Config (Get-Config) | ConvertTo-Json -Depth 6
    }
    "update-apply" {
        $cfg = Get-Config
        $r = Invoke-VSUpdateApply -Config $cfg -Force:$Force
        if ($r.ok) { Save-Config $cfg }
        $r | ConvertTo-Json -Depth 6
    }
    "rollback" {
        Invoke-VSRollbackLkg | ConvertTo-Json -Depth 4
    }
    "lkg-save" {
        @{ ok = $true; path = (Save-VSLastKnownGood -Config (Get-Config)) } | ConvertTo-Json
    }
    "install" { Install-VSAgent }
    "uninstall" {
        try { Unregister-ScheduledTask -TaskName "VectorStryke" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        if (Test-Path $Global:VSPaths.PidFile) {
            try {
                $pidVal = [int](Get-Content $Global:VSPaths.PidFile -Raw).Trim()
                Stop-Process -Id $pidVal -Force -ErrorAction SilentlyContinue
            } catch {}
            Remove-Item $Global:VSPaths.PidFile -Force -ErrorAction SilentlyContinue
        }
        Write-Host "Uninstalled scheduled task and stopped engine." -ForegroundColor Cyan
    }
    "dashboard" {
        $dash = Join-Path $Global:VSPaths.Root "dashboard.html"
        if (Test-Path $dash) { Start-Process $dash }
        else { Write-Host "dashboard.html not found" -ForegroundColor Yellow }
    }
    default {
        Write-Host @"

VectorStryke v$($Global:VSPaths.Version) — Modular Anti-Ransomware (Windows)
Usage: .\VectorStryke.ps1 <command> [-Id <value>] [-Force]

Core: install | uninstall | start | stop | status | scan
  approve -Id <AlertId> | deny -Id <AlertId>
mode -Id Automatic|Manual | auto-on | auto-off
health | ossec-status | osscan | canary-init | canary-verify
checkpoint | impact-clear [-Force]
update-check | update-apply [-Force] | lkg-save | rollback

"@
    }
}
