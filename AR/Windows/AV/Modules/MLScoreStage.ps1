#Requires -Version 5.1
class MLScoreStage : VSPipelineStage {
    MLScoreStage([VSRunContext]$ctx) : base($ctx) { }
    [void] Process([VSFileInfo]$fi) {
        $onnxPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Resources\pe_meta.onnx'
        if ((Test-Path $onnxPath) -and $this.TryOnnx($fi, $onnxPath)) { return }
        $fi.MLScore = $this.HeuristicPEScore($fi)
    }
    hidden [bool] TryOnnx([VSFileInfo]$fi, [string]$modelPath) {
        try {
            if (-not $this.Context.Cache.MLSession) {
                Add-Type -AssemblyName 'Microsoft.ML.OnnxRuntime' -ErrorAction Stop
                $this.Context.Cache.MLSession = [Microsoft.ML.OnnxRuntime.InferenceSession]::new($modelPath)
            }
            return $false
        } catch {
            return $false
        }
    }
    hidden [double] HeuristicPEScore([VSFileInfo]$fi) {
        $score = 0.1
        if (-not $fi.IsSigned) { $score += 0.25 }
        if ($fi.Entropy -gt 7.2) { $score += 0.35 }
        if ($fi.Entropy -gt 7.8) { $score += 0.15 }
        $ageHours = ([datetime]::UtcNow - $fi.LastWriteTimeUtc).TotalHours
        if ($ageHours -lt 24) { $score += 0.1 }
        return [Math]::Min(1.0, [Math]::Round($score, 3))
    }
}
