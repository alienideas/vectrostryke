#Requires -Version 5.1
class VSCache {
    [hashtable] $HashIndex   = @{}
    [hashtable] $Remote      = @{}
    [object]    $MLSession   = $null
}

class VSCounters {
    [int] $FilesScanned   = 0
    [int] $FilesQuarantined = 0
    [int] $FilesDeleted   = 0
    [int] $FilesSkipped   = 0
    [int] $Errors         = 0
}

class VSOptions {
    [ValidateSet('FullScan','QuickScan','UpdateIndex')]
    [string] $Mode      = 'FullScan'
    [int]    $Threads   = 2
    [bool]   $Quiet     = $false
    [string] $Ui        = 'Html'
    [string] $LogLevel  = 'Info'
}

class VSRunContext {
    [guid]      $RunId
    [datetime]  $StartTimeUtc
    [VSConfig]  $Config
    [VSOptions] $Options
    [VSCache]   $Cache
    [VSCounters]$Counters
    [System.Collections.Generic.List[object]] $Pipeline
    [System.Collections.Generic.List[VSFileInfo]] $FileCollection
    [System.Collections.Concurrent.BlockingCollection[VSFileInfo]] $QuarantineQueue
    [string]    $TempPath

    VSRunContext([VSConfig]$cfg, [VSOptions]$opts) {
        $this.RunId         = [guid]::NewGuid()
        $this.StartTimeUtc  = [datetime]::UtcNow
        $this.Config        = $cfg
        $this.Options       = $opts
        $this.Cache         = [VSCache]::new()
        $this.Counters      = [VSCounters]::new()
        $this.Pipeline      = [System.Collections.Generic.List[object]]::new()
        $this.FileCollection= [System.Collections.Generic.List[VSFileInfo]]::new()
        $this.QuarantineQueue = [System.Collections.Concurrent.BlockingCollection[VSFileInfo]]::new()
        $this.TempPath      = Join-Path $env:TEMP "VectorStrykeAV_$($this.RunId)"
        if (-not (Test-Path $this.TempPath)) {
            New-Item -ItemType Directory -Path $this.TempPath -Force | Out-Null
        }
        foreach ($d in @($cfg.QuarantinePath, $cfg.ReportPath)) {
            if (-not (Test-Path $d)) {
                New-Item -ItemType Directory -Path $d -Force | Out-Null
            }
        }
    }

    [void] Cleanup() {
        if (Test-Path $this.TempPath) {
            Remove-Item -LiteralPath $this.TempPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
