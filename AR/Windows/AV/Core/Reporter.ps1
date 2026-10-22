#Requires -Version 5.1
class VSReporter {
    [VSRunContext] $Ctx
    VSReporter([VSRunContext]$ctx) { $this.Ctx = $ctx }

    [void] ExportAll() {
        $outDir = $this.Ctx.Config.ReportPath
        if (-not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $jsonl = Join-Path $outDir "Report_$stamp.jsonl"
        $html  = Join-Path $outDir "Report_$stamp.html"

        foreach ($fi in $this.Ctx.FileCollection) {
            $fi.ToReportItem() | ConvertTo-Json -Compress -Depth 4 |
                Add-Content -Path $jsonl -Encoding UTF8
        }

        $summary = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VectorStryke AV Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#0f172a;color:#e2e8f0}
h1{color:#38bdf8} table{border-collapse:collapse;width:100%}
th,td{border:1px solid #334155;padding:6px 8px;font-size:13px}
th{background:#1e293b} .mal{color:#f87171} .qua{color:#fbbf24} .clean{color:#4ade80}
.card{background:#1e293b;padding:16px;border-radius:8px;display:inline-block;margin:4px}
</style></head><body>
<h1>VectorStryke AV Scan Report</h1>
<div class="card"><b>Run ID</b><br>$($this.Ctx.RunId)</div>
<div class="card"><b>Mode</b><br>$($this.Ctx.Options.Mode)</div>
<div class="card"><b>Scanned</b><br>$($this.Ctx.Counters.FilesScanned)</div>
<div class="card"><b>Quarantined</b><br>$($this.Ctx.Counters.FilesQuarantined)</div>
<table>
<tr><th>File</th><th>Score</th><th>Class</th><th>Entropy</th><th>ML</th><th>Signed</th><th>Action</th></tr>
"@
        foreach ($fi in ($this.Ctx.FileCollection | Sort-Object Score -Descending)) {
            $cls = switch ($fi.Classification) {
                'Malicious'  { 'mal' }
                'Quarantine' { 'qua' }
                default      { 'clean' }
            }
            $summary += "<tr><td>$($fi.FullName)</td><td>$($fi.Score)</td>"
            $summary += "<td class='$cls'>$($fi.Classification)</td>"
            $summary += "<td>$($fi.Entropy)</td><td>$($fi.MLScore)</td>"
            $summary += "<td>$($fi.IsSigned)</td><td>$($fi.ActionTaken)</td></tr>`n"
        }
        $summary += "</table></body></html>"
        Set-Content -Path $html -Value $summary -Encoding UTF8
        if (Get-Command Write-VSLog -ErrorAction SilentlyContinue) {
            Write-VSLog "Reports written: $jsonl  |  $html"
        }
    }
}
