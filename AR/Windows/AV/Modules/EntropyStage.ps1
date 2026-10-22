#Requires -Version 5.1
class EntropyStage : VSPipelineStage {
    EntropyStage([VSRunContext]$ctx) : base($ctx) { }
    [void] Process([VSFileInfo]$fi) {
        if ($fi.Length -gt 32MB) {
            $fi.Entropy = 0.0
            return
        }
        try {
            $bytes = [IO.File]::ReadAllBytes($fi.FullName)
            if ($bytes.Length -eq 0) {
                $fi.Entropy = 0.0
                return
            }
            $hist = @{}
            foreach ($b in $bytes) {
                if ($hist.ContainsKey($b)) { $hist[$b]++ } else { $hist[$b] = 1 }
            }
            $len = [double]$bytes.Length
            $entropy = 0.0
            foreach ($c in $hist.Values) {
                $p = $c / $len
                $entropy -= $p * [Math]::Log($p, 2)
            }
            $fi.Entropy = [Math]::Round($entropy, 2)
        } catch {
            $fi.Entropy = 0.0
            $this.Context.Counters.Errors++
        }
    }
}
