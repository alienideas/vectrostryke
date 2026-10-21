"""Weighted scoring → accept / quarantine / reject."""
from __future__ import annotations

from typing import Dict, List

from asg.models import FactorResult, Verdict


def decide(factors: List[FactorResult], thresholds: Dict[str, float]) -> Verdict:
    for f in factors:
        if f.hard_reject:
            return Verdict(
                decision="reject",
                score=100.0,
                reasons=[f"{f.name}:{f.detail}"],
                factors=factors,
            )
    score = sum(f.score for f in factors)
    score = max(0.0, min(100.0, score))
    reasons = [f"{f.name}:{f.detail}" for f in factors if f.score > 0 or f.hard_reject]
    accept_max = float(thresholds.get("accept_max", 40))
    quarantine_max = float(thresholds.get("quarantine_max", 70))
    if score <= accept_max:
        decision = "accept"
    elif score <= quarantine_max:
        decision = "quarantine"
    else:
        decision = "reject"
    return Verdict(decision=decision, score=score, reasons=reasons, factors=factors)
