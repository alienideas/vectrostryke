#Requires -Version 5.1
class VSQuarantine {
    [VSRunContext] $Ctx
    [string] $ContainerPath
    [string] $ManifestPath

    VSQuarantine([VSRunContext]$ctx) {
        $this.Ctx           = $ctx
        $this.ContainerPath = $ctx.Config.QuarantinePath
        $this.ManifestPath  = Join-Path $this.ContainerPath 'manifest.jsonl'
        if (-not (Test-Path $this.ContainerPath)) {
            New-Item -ItemType Directory -Path $this.ContainerPath -Force | Out-Null
        }
    }

    [void] Add([VSFileInfo]$fi) {
        $guid = [guid]::NewGuid().ToString('N')
        $dest = Join-Path $this.ContainerPath "$guid.qz"
        try {
            $entropy = [Text.Encoding]::UTF8.GetBytes("VectorStrykeAV-$($this.Ctx.RunId)")
            $keyMaterial = [Security.Cryptography.ProtectedData]::Protect(
                [Text.Encoding]::UTF8.GetBytes($env:USERNAME + $env:COMPUTERNAME),
                $entropy,
                [Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            $key = $keyMaterial[0..31]
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.KeySize = 256
            $aes.Key     = $key
            $aes.GenerateIV()
            $iv = $aes.IV
            $plain = [IO.File]::ReadAllBytes($fi.FullName)
            $encryptor = $aes.CreateEncryptor()
            $cipher = $encryptor.TransformFinalBlock($plain, 0, $plain.Length)
            $payload = $iv + $cipher
            [IO.File]::WriteAllBytes($dest, $payload)
            $entry = [pscustomobject]@{
                Id             = $guid
                OriginalPath   = $fi.FullName
                Sha256         = $fi.HashSha256
                Score          = $fi.Score
                Classification = $fi.Classification
                TimestampUtc   = [datetime]::UtcNow.ToString('o')
                QuarantineFile = $dest
            }
            $entry | ConvertTo-Json -Compress | Add-Content -Path $this.ManifestPath -Encoding UTF8
            $fi.ActionTaken = 'Quarantined'
            $this.Ctx.Counters.FilesQuarantined++
            Write-VSLog "Quarantined $($fi.FullName) → $dest"
        } catch {
            Write-VSLog "Quarantine failed for $($fi.FullName): $_" 'Error'
            $this.Ctx.Counters.Errors++
        }
    }

    [void] ReviewAndApply() {
        $candidates = $this.Ctx.FileCollection | Where-Object { $_.Classification -in @('Quarantine','Malicious') }
        if ($candidates.Count -eq 0) {
            Write-VSLog "No items require quarantine review"
            return
        }
        foreach ($fi in $candidates) {
            if ($fi.Classification -eq 'Malicious' -or $this.Ctx.Options.Quiet) {
                $this.Add($fi)
                if ($fi.Classification -eq 'Malicious' -and -not $this.IsProtectedPath($fi.FullName)) {
                    $fi.ActionTaken = 'Quarantined (pending delete review)'
                }
            } else {
                $this.Add($fi)
            }
        }
        $this.ShowReviewHtml($candidates)
    }

    hidden [bool] IsProtectedPath([string]$path) {
        $protected = @('\Windows\', '\Program Files\', '\Program Files (x86)\')
        $norm = $path.ToLowerInvariant()
        foreach ($p in $protected) {
            if ($norm -like "*$($p.ToLowerInvariant())*") { return $true }
        }
        return $false
    }

    hidden [void] ShowReviewHtml([object[]]$items) {
        $html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VectorStryke AV – Quarantine Review</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#0f172a;color:#e2e8f0}
h1{color:#38bdf8} table{border-collapse:collapse;width:100%}
th,td{border:1px solid #334155;padding:8px;text-align:left}
th{background:#1e293b}
</style></head><body>
<h1>VectorStryke AV – Quarantine Review</h1>
<p>Run $($this.Ctx.RunId)</p>
<table>
<tr><th>Path</th><th>Score</th><th>Class</th><th>SHA-256</th><th>Action</th></tr>
"@
        foreach ($fi in $items) {
            $html += "<tr><td>$($fi.FullName)</td><td>$($fi.Score)</td>"
            $html += "<td>$($fi.Classification)</td><td><code>$($fi.HashSha256)</code></td>"
            $html += "<td>$($fi.ActionTaken)</td></tr>`n"
        }
        $html += "</table></body></html>"
        $out = Join-Path $this.Ctx.Config.ReportPath ("QuarantineReview_{0:yyyyMMdd_HHmmss}.html" -f (Get-Date))
        Set-Content -Path $out -Value $html -Encoding UTF8
        Write-VSLog "Review UI written to $out"
        if (-not $this.Ctx.Options.Quiet) {
            Start-Process $out -ErrorAction SilentlyContinue
        }
    }
}
