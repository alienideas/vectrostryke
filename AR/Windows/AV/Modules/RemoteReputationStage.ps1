#Requires -Version 5.1
class RemoteReputationStage : VSPipelineStage {
    RemoteReputationStage([VSRunContext]$ctx) : base($ctx) { }
    [void] Process([VSFileInfo]$fi) {
        if (-not $fi.HashSha256) { return }
        $hash = $fi.HashSha256
        if ($this.Context.Cache.Remote.ContainsKey($hash)) {
            $fi.RemoteReputation = $this.Context.Cache.Remote[$hash]
            return
        }
        $apiKey = $env:VS_VT_APIKEY
        if (-not $apiKey) {
            try {
                $apiKey = Get-Secret -Name $this.Context.Config.ApiKeyVaultName -AsPlainText -ErrorAction Stop
            } catch { }
        }
        if (-not $apiKey) {
            $fi.RemoteReputation = $null
            return
        }
        try {
            $uri = "https://www.virustotal.com/api/v3/files/$hash"
            $headers = @{ 'x-apikey' = $apiKey }
            $json = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 8 -ErrorAction Stop
            $stats = $json.data.attributes.last_analysis_stats
            $mal   = [double]$stats.malicious
            $total = $mal + [double]$stats.harmless + [double]$stats.suspicious + [double]$stats.undetected
            $rep = if ($total -gt 0) { $mal / $total } else { 0.0 }
            $fi.RemoteReputation = [Math]::Round($rep, 3)
            $this.Context.Cache.Remote[$hash] = $fi.RemoteReputation
        } catch {
            $fi.RemoteReputation = $null
        }
    }
}
