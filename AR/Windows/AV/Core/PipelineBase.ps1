#Requires -Version 5.1
class VSPipelineStage {
    [VSRunContext] $Context
    [string]       $Name
    VSPipelineStage([VSRunContext]$ctx) {
        $this.Context = $ctx
        $this.Name    = $this.GetType().Name
    }
    [void] Process([VSFileInfo]$fileInfo) {
        throw "Process() not implemented in $($this.Name)"
    }
}
