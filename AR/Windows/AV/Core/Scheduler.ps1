#Requires -Version 5.1
class VSScheduler {
    [VSRunContext] $Ctx
    [System.Collections.Concurrent.BlockingCollection[VSFileInfo]] $Queue
    [System.Collections.Generic.List[System.Management.Automation.Job]] $Jobs

    VSScheduler([VSRunContext]$ctx) {
        $this.Ctx   = $ctx
        $this.Queue = [System.Collections.Concurrent.BlockingCollection[VSFileInfo]]::new(10000)
        $this.Jobs  = [System.Collections.Generic.List[System.Management.Automation.Job]]::new()
    }

    [void] EnqueueFiles() {
        $roots = $this.Ctx.Config.SafeZones
        if ($this.Ctx.Options.Mode -eq 'QuickScan') {
            $roots = @(
                $env:USERPROFILE,
                "$env:USERPROFILE\Downloads",
                "$env:USERPROFILE\Desktop"
            )
        }
        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            try {
                Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue |
                    Where-Object {
                        -not $this.Ctx.Config.IsExcluded($_.FullName) -and
                        $_.Length -gt 0 -and $_.Length -lt 100MB
                    } |
                    ForEach-Object {
                        try {
                            $fi = [VSFileInfo]::new($_.FullName)
                            $this.Queue.Add($fi)
                        } catch {
                            $this.Ctx.Counters.Errors++
                        }
                    }
            } catch {
                $this.Ctx.Counters.Errors++
            }
        }
        $this.Queue.CompleteAdding()
    }

    [void] StartRunspaceWorkers() {
        $pool = [runspacefactory]::CreateRunspacePool(1, $this.Ctx.Options.Threads)
        $pool.Open()
        $handles = @()
        $script = {
            param($fileInfo, $stages)
            foreach ($stage in $stages) {
                try { $stage.Process($fileInfo) } catch { }
            }
            return $fileInfo
        }
        while ($this.Queue.Count -gt 0 -or -not $this.Queue.IsCompleted) {
            $fi = $null
            if ($this.Queue.TryTake([ref]$fi, 200)) {
                $ps = [powershell]::Create().AddScript($script).AddArgument($fi).AddArgument($this.Ctx.Pipeline)
                $ps.RunspacePool = $pool
                $handles += [pscustomobject]@{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
            } else {
                Start-Sleep -Milliseconds 50
            }
        }
        foreach ($h in $handles) {
            try {
                $result = $h.PowerShell.EndInvoke($h.Handle)
                if ($result) {
                    $this.Ctx.FileCollection.Add($result[0])
                    $this.Ctx.Counters.FilesScanned++
                }
            } catch {
                $this.Ctx.Counters.Errors++
            } finally {
                $h.PowerShell.Dispose()
            }
        }
        $pool.Close()
        $pool.Dispose()
    }

    [void] WaitForCompletion() {
        if ($this.Jobs.Count -gt 0) {
            Wait-Job -Job $this.Jobs | Out-Null
            foreach ($j in $this.Jobs) {
                Receive-Job $j -ErrorAction SilentlyContinue | Out-Null
                Remove-Job $j -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
