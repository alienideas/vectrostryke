#Requires -Version 5.1
class VSConfig {
    [string[]] $Exclusions      = @()
    [string[]] $SafeZones       = @()
    [string]   $IndexPath       = "$env:ProgramData\VectorStryke\AV\hashindex.json"
    [string]   $QuarantinePath  = "$env:ProgramData\VectorStryke\AV\Quarantine"
    [string]   $ReportPath      = "$env:ProgramData\VectorStryke\AV\Reports"
    [string]   $ApiKeyVaultName = 'VTKey'
    [hashtable]$PipelineOrder   = @{
        HashStage              = 10
        SignatureStage         = 20
        EntropyStage           = 30
        MLScoreStage           = 40
        RemoteReputationStage  = 50
    }
    [int]      $DefaultThreads  = 2
    [double]   $QuarantineThreshold = 0.20
    [double]   $MaliciousThreshold  = 0.60

    VSConfig() {
        $this.SafeZones = @(
            "$env:SystemDrive\",
            "$env:ProgramFiles",
            "${env:ProgramFiles(x86)}",
            "$env:USERPROFILE"
        )
        $this.Exclusions = @(
            '\Windows\WinSxS\',
            '\Windows\Temp\',
            '\Windows\SoftwareDistribution\',
            '\ProgramData\Microsoft\Windows Defender\',
            '\ProgramData\VectorStryke\',
            '\AppData\Local\Temp\'
        )
    }

    [bool] IsExcluded([string]$fullPath) {
        $norm = $fullPath.ToLowerInvariant()
        foreach ($ex in $this.Exclusions) {
            if ($norm -like "*$($ex.ToLowerInvariant())*") { return $true }
        }
        return $false
    }

    static [VSConfig] LoadFromJson([string]$path) {
        if (Test-Path $path) {
            $json = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            $cfg = [VSConfig]::new()
            if ($json.Exclusions)   { $cfg.Exclusions   = @($json.Exclusions) }
            if ($json.SafeZones)    { $cfg.SafeZones    = @($json.SafeZones) }
            if ($json.IndexPath)    { $cfg.IndexPath    = $json.IndexPath }
            if ($json.DefaultThreads){ $cfg.DefaultThreads = [int]$json.DefaultThreads }
            return $cfg
        }
        return [VSConfig]::new()
    }
}
