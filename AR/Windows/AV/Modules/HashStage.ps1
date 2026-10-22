#Requires -Version 5.1
class HashStage : VSPipelineStage {
    hidden static [byte[]] $Buffer = [byte[]]::new(65536)
    HashStage([VSRunContext]$ctx) : base($ctx) { }
    [void] Process([VSFileInfo]$fi) {
        if ($fi.HashSha256) { return }
        try {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $stream = [IO.File]::OpenRead($fi.FullName)
            try {
                while (($read = $stream.Read([HashStage]::Buffer, 0, [HashStage]::Buffer.Length)) -gt 0) {
                    $sha.TransformBlock([HashStage]::Buffer, 0, $read, $null, 0) | Out-Null
                }
                $sha.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null
                $fi.HashSha256 = [BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant()
            } finally {
                $stream.Dispose()
                $sha.Dispose()
            }
        } catch {
            $fi.HashSha256 = $null
            $this.Context.Counters.Errors++
        }
    }
}
