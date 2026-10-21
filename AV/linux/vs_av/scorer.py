"""Bayesian risk scoring – mirrors Windows VSScorer."""
from __future__ import annotations

from .models import VSFileInfo


class VSScorer:
    P_MAL = 0.001
    P_CLEAN = 0.999

    LIK = {
        "sig_valid": (0.01, 0.99),
        "sig_invalid": (0.90, 0.10),
        "ent_high": (0.80, 0.20),
        "ent_low": (0.20, 0.80),
        "ml_high": (0.85, 0.15),
        "ml_low": (0.15, 0.85),
        "vt_high": (0.95, 0.05),
        "vt_low": (0.05, 0.95),
    }

    @classmethod
    def compute_score(cls, fi: VSFileInfo) -> float:
        l_mal, l_clean = 1.0, 1.0

        if fi.is_signed and fi.signature_status in ("Valid", "SystemPath"):
            m, c = cls.LIK["sig_valid"]
        else:
            m, c = cls.LIK["sig_invalid"]
        l_mal *= m
        l_clean *= c

        if fi.entropy > 7.5:
            m, c = cls.LIK["ent_high"]
        else:
            m, c = cls.LIK["ent_low"]
        l_mal *= m
        l_clean *= c

        if fi.ml_score > 0.6:
            m, c = cls.LIK["ml_high"]
        else:
            m, c = cls.LIK["ml_low"]
        l_mal *= m
        l_clean *= c

        if fi.remote_reputation is not None:
            if fi.remote_reputation > 0.5:
                m, c = cls.LIK["vt_high"]
            else:
                m, c = cls.LIK["vt_low"]
            l_mal *= m
            l_clean *= c

        posterior = (l_mal * cls.P_MAL) / ((l_mal * cls.P_MAL) + (l_clean * cls.P_CLEAN))
        return round(posterior, 3)

    @classmethod
    def classify(cls, score: float, q_thresh: float = 0.20, m_thresh: float = 0.60) -> str:
        if score <= q_thresh:
            return "Clean"
        if score <= m_thresh:
            return "Quarantine"
        return "Malicious"
