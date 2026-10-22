#Requires -Version 5.1
class SignatureStage : VSPipelineStage {
    SignatureStage([VSRunContext]$ctx) : base($ctx) { }
    [void] Process([VSFileInfo]$fi) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $fi.FullName -ErrorAction Stop
            $fi.IsSigned        = ($null -ne $sig.SignerCertificate)
            $fi.SignatureStatus = $sig.Status.ToString()
        } catch {
            $fi.IsSigned        = $false
            $fi.SignatureStatus = 'Error'
        }
    }
}
