#Requires -Version 5.1
class VSScorer {
    static [double] $PMalicious = 0.001
    static [double] $PClean     = 0.999
    static [hashtable] $Lik = @{
        SigValid   = @{ Mal = 0.01; Clean = 0.99 }
        SigInvalid = @{ Mal = 0.90; Clean = 0.10 }
        EntHigh    = @{ Mal = 0.80; Clean = 0.20 }
        EntLow     = @{ Mal = 0.20; Clean = 0.80 }
        MLHigh     = @{ Mal = 0.85; Clean = 0.15 }
        MLLow      = @{ Mal = 0.15; Clean = 0.85 }
        VTHigh     = @{ Mal = 0.95; Clean = 0.05 }
        VTLow      = @{ Mal = 0.05; Clean = 0.95 }
    }
    static [double] ComputeScore([VSFileInfo]$fi) {
        $Lmal   = 1.0
        $Lclean = 1.0
        if ($fi.IsSigned -and $fi.SignatureStatus -eq 'Valid') {
            $Lmal   *= [VSScorer]::Lik.SigValid.Mal
            $Lclean *= [VSScorer]::Lik.SigValid.Clean
        } else {
            $Lmal   *= [VSScorer]::Lik.SigInvalid.Mal
            $Lclean *= [VSScorer]::Lik.SigInvalid.Clean
        }
        if ($fi.Entropy -gt 7.5) {
            $Lmal   *= [VSScorer]::Lik.EntHigh.Mal
            $Lclean *= [VSScorer]::Lik.EntHigh.Clean
        } else {
            $Lmal   *= [VSScorer]::Lik.EntLow.Mal
            $Lclean *= [VSScorer]::Lik.EntLow.Clean
        }
        if ($fi.MLScore -gt 0.6) {
            $Lmal   *= [VSScorer]::Lik.MLHigh.Mal
            $Lclean *= [VSScorer]::Lik.MLHigh.Clean
        } else {
            $Lmal   *= [VSScorer]::Lik.MLLow.Mal
            $Lclean *= [VSScorer]::Lik.MLLow.Clean
        }
        if ($null -ne $fi.RemoteReputation) {
            if ($fi.RemoteReputation -gt 0.5) {
                $Lmal   *= [VSScorer]::Lik.VTHigh.Mal
                $Lclean *= [VSScorer]::Lik.VTHigh.Clean
            } else {
                $Lmal   *= [VSScorer]::Lik.VTLow.Mal
                $Lclean *= [VSScorer]::Lik.VTLow.Clean
            }
        }
        $posterior = ($Lmal * [VSScorer]::PMalicious) /
                     (($Lmal * [VSScorer]::PMalicious) + ($Lclean * [VSScorer]::PClean))
        return [Math]::Round($posterior, 3)
    }
    static [string] Classify([double]$score, [double]$qThresh = 0.20, [double]$mThresh = 0.60) {
        if ($score -le $qThresh) { return 'Clean' }
        if ($score -le $mThresh) { return 'Quarantine' }
        return 'Malicious'
    }
}
