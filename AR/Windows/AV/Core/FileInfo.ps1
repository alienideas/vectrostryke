#Requires -Version 5.1
class VSFileInfo {
    [string]   $FullName
    [long]     $Length
    [datetime] $CreationTimeUtc
    [datetime] $LastWriteTimeUtc
    [string]   $OwnerSid
    [bool]     $IsSigned            = $false
    [string]   $SignatureStatus     = 'NotSigned'
    [string]   $HashSha256          = $null
    [double]   $Entropy             = 0.0
    [double]   $MLScore             = 0.0
    [nullable[double]] $RemoteReputation = $null
    [double]   $Score               = 0.0
    [ValidateSet('Clean','Quarantine','Malicious')]
    [string]   $Classification      = 'Clean'
    [string]   $ActionTaken         = 'None'

    VSFileInfo([string]$path) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "File not found: $path"
        }
        $this.FullName = $path
        $fi = Get-Item -LiteralPath $path -Force
        $this.Length          = $fi.Length
        $this.CreationTimeUtc = $fi.CreationTimeUtc
        $this.LastWriteTimeUtc= $fi.LastWriteTimeUtc
        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            $this.OwnerSid = $acl.Owner
        } catch {
            $this.OwnerSid = 'Unknown'
        }
    }

    [pscustomobject] ToReportItem() {
        return [pscustomobject]@{
            FilePath       = $this.FullName
            Score          = $this.Score
            Classification = $this.Classification
            ActionTaken    = $this.ActionTaken
            TimestampUtc   = [datetime]::UtcNow.ToString('o')
            HashSha256     = $this.HashSha256
            Entropy        = $this.Entropy
            MLScore        = $this.MLScore
            IsSigned       = $this.IsSigned
        }
    }
}
