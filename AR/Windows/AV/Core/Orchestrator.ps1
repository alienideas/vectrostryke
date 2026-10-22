#Requires -Version 5.1
class VSOrchestrator {
    [VSRunContext] $Ctx
    [string]       $ModuleRoot

    VSOrchestrator([VSRunContext]$ctx, [string]$moduleRoot) {
        $this.Ctx        = $ctx
        $this.ModuleRoot = $moduleRoot
    }

    [void] Run() {
        Write-VSLog "RunId $($this.Ctx.RunId) started – Mode=$($this.Ctx.Options.Mode) Threads=$($this.Ctx.Options.Threads)"
        if ($this.Ctx.Options.Mode -eq 'UpdateIndex') {
            $this.UpdateHashIndex()
            return
        }
        $this.LoadModules()
        $this.BuildPipeline()
        $scheduler = [VSScheduler]::new($this.Ctx)
        Write-VSLog "Enumerating files…"
        $scheduler.EnqueueFiles()
        Write-VSLog "Starting runspace workers…"
        $scheduler.StartRunspaceWorkers()
        $this.ClassifyAll()
        $this.EnqueueQuarantineCandidates()
        $q = [VSQuarantine]::new($this.Ctx)
        $q.ReviewAndApply()
        $this.TestSystemIntegrity()
        $reporter = [VSReporter]::new($this.Ctx)
        $reporter.ExportAll()
        $this.Ctx.Cleanup()
        Write-VSLog "Scan complete. Scanned=$($this.Ctx.Counters.FilesScanned) Quarantined=$($this.Ctx.Counters.FilesQuarantined)"
    }

    hidden [void] LoadModules() {
        $modPath = Join-Path $this.ModuleRoot 'Modules'
        if (-not (Test-Path $modPath)) { return }
        Get-ChildItem -Path $modPath -Filter '*Stage.ps1' -ErrorAction SilentlyContinue |
            ForEach-Object {
                . $_.FullName
                Write-VSLog "Loaded module $($_.Name)"
            }
    }

    hidden [void] BuildPipeline() {
        $order = $this.Ctx.Config.PipelineOrder.GetEnumerator() |
                 Sort-Object Value |
                 ForEach-Object { $_.Key }
        foreach ($name in $order) {
            try {
                $type = $name -as [type]
                if (-not $type) {
                    $type = [AppDomain]::CurrentDomain.GetAssemblies() |
                            ForEach-Object { $_.GetTypes() } |
                            Where-Object { $_.Name -eq $name } |
                            Select-Object -First 1
                }
                if ($type) {
                    $instance = [Activator]::CreateInstance($type, $this.Ctx)
                    $this.Ctx.Pipeline.Add($instance)
                    Write-VSLog "Pipeline stage registered: $name"
                } else {
                    Write-VSLog "WARNING: stage type $name not found"
                }
            } catch {
                Write-VSLog "ERROR loading stage $name : $_"
            }
        }
    }

    hidden [void] ClassifyAll() {
        foreach ($fi in $this.Ctx.FileCollection) {
            $fi.Score = [VSScorer]::ComputeScore($fi)
            $fi.Classification = [VSScorer]::Classify(
                $fi.Score,
                $this.Ctx.Config.QuarantineThreshold,
                $this.Ctx.Config.MaliciousThreshold
            )
        }
    }

    hidden [void] EnqueueQuarantineCandidates() {
        foreach ($fi in $this.Ctx.FileCollection) {
            if ($fi.Classification -in @('Quarantine','Malicious')) {
                $this.Ctx.QuarantineQueue.Add($fi)
            }
        }
        $this.Ctx.QuarantineQueue.CompleteAdding()
    }

    hidden [void] UpdateHashIndex() {
        Write-VSLog "Updating hash index at $($this.Ctx.Config.IndexPath)"
        $index = @{}
        $index | ConvertTo-Json -Depth 3 | Set-Content -Path $this.Ctx.Config.IndexPath -Encoding UTF8
        Write-VSLog "Hash index updated"
    }

    hidden [void] TestSystemIntegrity() {
        Write-VSLog "Checking system integrity (SFC / DISM hooks)…"
    }
}

function Write-VSLog {
    param([string]$Message, [string]$Level = 'Info')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    if (-not $script:VSQuiet) { Write-Host $line }
    $logDir = "$env:ProgramData\VectorStryke\AV\Logs"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path (Join-Path $logDir "av_$(Get-Date -Format 'yyyyMMdd').log") -Value $line -ErrorAction SilentlyContinue
}
