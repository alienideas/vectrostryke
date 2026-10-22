# VectorStryke OS Security Scanner (Windows)

function Initialize-VSOsScanEnv {
    param([hashtable]$Config)
    $work = if ($Config.OsScanTempDir) { $Config.OsScanTempDir } else { Join-Path $env:TEMP "VectorStryke_AVScan" }
    if (-not (Test-Path $work)) { New-Item -ItemType Directory -Path $work -Force | Out-Null }
    $q = if ($Config.OsScanQuarantineDir) { $Config.OsScanQuarantineDir } else { Join-Path $Global:VSPaths.DataDir "OsScanQuarantine" }
    if (-not (Test-Path $q)) { New-Item -ItemType Directory -Path $q -Force | Out-Null }
    $baseline = Join-Path $Global:VSPaths.DataDir "osscan_baseline.csv"
    $exclFile = if ($Config.OsScanExclusionsFile) { $Config.OsScanExclusionsFile } else { Join-Path $Global:VSPaths.DataDir "osscan_exclusions.txt" }
    if (-not (Test-Path $exclFile)) {
        "# exclusions`nC:\Windows\WinSxS`nC:\`$Recycle.Bin" | Set-Content $exclFile -Encoding UTF8
    }
    return @{ WorkDir = $work; QuarantineDir = $q; BaselineCsv = $baseline; ExclusionsFile = $exclFile; ManifestLog = Join-Path $q "quarantine.log" }
}

function Get-VSOsScanExclusions {
    param($Env, [hashtable]$Config)
    $list = @()
    if (Test-Path $Env.ExclusionsFile) {
        Get-Content $Env.ExclusionsFile -ErrorAction SilentlyContinue | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith("#")) { $list += $line }
        }
    }
    foreach ($p in @($Config.OsScanExtraExclusions)) { if ($p) { $list += $p } }
    return $list
}

function Test-VSOsScanExcluded {
    param([string]$Path, [string[]]$Exclusions)
    foreach ($ex in $Exclusions) {
        if (-not $ex) { continue }
        if ($Path.StartsWith($ex, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($Path -like $ex) { return $true }
    }
    return $false
}

function Get-VSFileSha256 {
    param([string]$Path)
    try { return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { return $null }
}

function Get-VSFileEntropy {
    param([string]$Path)
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -eq 0 -or $bytes.Length -gt 32MB) { return 0.0 }
        $hist = @{}
        foreach ($b in $bytes) { if ($hist.ContainsKey($b)) { $hist[$b]++ } else { $hist[$b] = 1 } }
        $len = [double]$bytes.Length; $ent = 0.0
        foreach ($c in $hist.Values) { $p = $c / $len; $ent -= $p * [Math]::Log($p, 2) }
        return [Math]::Round($ent, 3)
    } catch { return 0.0 }
}

function Test-VSSuspiciousStrings {
    param([string]$Path)
    $hits = @()
    $patterns = @("powershell -enc","downloadstring","frombase64string","invoke-expression","mimikatz","virtualalloc")
    try {
        if ((Get-Item $Path).Length -gt 5MB) { return $hits }
        $text = [IO.File]::ReadAllText($Path).ToLower()
        foreach ($p in $patterns) { if ($text -like "*$p*") { $hits += $p } }
    } catch {}
    return $hits
}

function Get-VSSignatureStatus {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { return 'Valid' }
        if ($sig.SignerCertificate) { return 'Invalid' }
        return 'Missing'
    } catch { return 'Error' }
}

function Get-VSThreatScore {
    param([string]$SigStatus, [double]$Entropy, [int]$StringHits, [bool]$ExternalHit)
    $s = 0
    if ($SigStatus -eq 'Valid') { $s += 0 }
    elseif ($SigStatus -eq 'Invalid') { $s += 50 }
    elseif ($SigStatus -eq 'Missing') { $s += 40 }
    else { $s += 15 }
    if ($Entropy -gt 7.0) { $s += [int](($Entropy - 7.0) / 0.5) * 10 }
    $s += $StringHits * 5
    if ($ExternalHit) { $s += 50 }
    return [Math]::Min($s, 100)
}

function Invoke-VSOsScan {
    param([hashtable]$Config, [string[]]$Roots = @(), [switch]$Full, [switch]$BuildBaselineOnly)
    $envScan = Initialize-VSOsScanEnv -Config $Config
    if ($BuildBaselineOnly) {
        return @{ ok = $true; note = "baseline_stub"; path = $envScan.BaselineCsv }
    }
    $ossec = @{ Class = "Unknown" }
    if (Get-Command Invoke-VSOsSecurityDetect -ErrorAction SilentlyContinue) {
        $ossec = Invoke-VSOsSecurityDetect -Config $Config
        Write-Log "OS-SEC pre-scan class=$($ossec.Class)" "INFO"
    }
    $exclusions = @(Get-VSOsScanExclusions -Env $envScan -Config $Config)
    if (-not $Roots -or $Roots.Count -eq 0) {
        if ($Full) { $Roots = @("$env:SystemDrive\") }
        else {
            $Roots = @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:TEMP","$env:PUBLIC") | Where-Object { Test-Path $_ }
        }
    }
    $extExec = @(".exe",".dll",".sys",".ps1",".vbs",".js",".bat",".cmd",".scr",".com")
    $results = @(); $scanned = 0
    $maxFiles = if ($Config.OsScanMaxFiles) { [int]$Config.OsScanMaxFiles } else { 2000 }
    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
            if ($scanned -ge $maxFiles) { return }
            $fp = $_.FullName
            if (Test-VSOsScanExcluded -Path $fp -Exclusions $exclusions) { return }
            $scanned++
            $ext = $_.Extension.ToLowerInvariant()
            $isExec = $extExec -contains $ext
            $sig = if ($isExec) { Get-VSSignatureStatus -Path $fp } else { "N/A" }
            $ent = if ($isExec) { Get-VSFileEntropy -Path $fp } else { 0.0 }
            $hits = if ($isExec -or $ext -in @(".ps1",".vbs",".js")) { @(Test-VSSuspiciousStrings -Path $fp) } else { @() }
            $score = Get-VSThreatScore -SigStatus $sig -Entropy $ent -StringHits $hits.Count -ExternalHit $false
            if (-not $isExec -and $score -gt 40) { $score = 40 }
            $tier = if ($score -le 30) { "Clean" } elseif ($score -le 70) { "Suspicious" } else { "Malicious" }
            if ($tier -eq "Clean") { return }
            $results += @{ Path = $fp; Size = $_.Length; Score = $score; Tier = $tier; Signature = $sig; Entropy = $ent; StringHits = $hits; Sha256 = (Get-VSFileSha256 -Path $fp); OsSecClass = $ossec.Class }
        }
    }
    $autoQ = $true
    if ($Config.ContainsKey("OsScanAutoQuarantine")) { $autoQ = [bool]$Config.OsScanAutoQuarantine }
    $actions = @()
    foreach ($r in $results) {
        if (-not $autoQ) { continue }
        $guid = [guid]::NewGuid().ToString("N")
        $dest = Join-Path $envScan.QuarantineDir $guid
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        try {
            $leaf = [IO.Path]::GetFileName($r.Path)
            Move-Item -Path $r.Path -Destination (Join-Path $dest $leaf) -Force -ErrorAction Stop
            $line = "{0}|{1}|{2}|{3}|{4}" -f (Get-Date -Format o), $r.Path, (Join-Path $dest $leaf), $r.Score, $r.Tier
            Add-Content -Path $envScan.ManifestLog -Value $line -Encoding UTF8
            $r.Quarantined = $true
            $actions += "Quarantined:$($r.Path)"
            Write-Log "OS scan quarantined score=$($r.Score) $($r.Path)" "HIGH"
        } catch {
            $r.Quarantined = $false
            Write-Log "OS scan quarantine failed $($r.Path): $_" "ERROR"
        }
    }
    $report = @{
        ScannedFiles = $scanned; Findings = $results; Actions = $actions
        OsSecClass = $ossec.Class; OsSecFallbackEligible = $ossec.FallbackEligible
        QuarantineDir = $envScan.QuarantineDir
        CompletedAt = (Get-Date).ToUniversalTime().ToString("o"); ExitCode = 0
    }
    $reportPath = Join-Path $Global:VSPaths.DataDir ("osscan_report_{0}.json" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $report | ConvertTo-Json -Depth 8 | Set-Content $reportPath -Encoding UTF8
    $report.ReportPath = $reportPath
    return $report
}

function Restore-VSOsScanQuarantine {
    param([string]$QuarantineFile, [string]$OriginalPath)
    if (-not (Test-Path $QuarantineFile)) { return @{ ok = $false; error = "not_found" } }
    try {
        $parent = Split-Path $OriginalPath -Parent
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Move-Item -Path $QuarantineFile -Destination $OriginalPath -Force
        return @{ ok = $true; restored = $OriginalPath }
    } catch { return @{ ok = $false; error = "$_" } }
}
