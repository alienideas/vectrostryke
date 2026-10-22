#Requires -Version 5.1
class CustomStageSample : VSPipelineStage {
    CustomStageSample([VSRunContext]$ctx) : base($ctx) { }
    [void] Process([VSFileInfo]$fi) {
        $name = [IO.Path]::GetFileName($fi.FullName)
        if ($name -match '\.(exe|dll|scr|js|vbs|ps1)\.(txt|jpg|pdf|doc)$') {
            $fi.MLScore = [Math]::Max($fi.MLScore, 0.75)
        }
    }
}
