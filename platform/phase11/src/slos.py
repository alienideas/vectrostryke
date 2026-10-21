"""Phase 11 — SLO definitions and evaluation (defaults from architecture)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class SLO:
    name: str
    description: str
    target: float
    unit: str
    higher_is_better: bool = False


DEFAULT_SLOS: List[SLO] = [
    SLO("decision_latency_p95_ms", "Local decision latency p95", 2000.0, "ms", False),
    SLO("evidence_write_success_pct", "Evidence write success rate", 99.9, "percent", True),
    SLO("pack_verify_load_sec", "Policy pack verify+load", 30.0, "sec", False),
    SLO("offline_protection_pct", "Core decide/act without control plane", 100.0, "percent", True),
    SLO("fp_budget_per_pack", "Declared false-positive budget (per pack tests)", 5.0, "percent", False),
]


@dataclass
class SLOSample:
    name: str
    observed: float
    passed: bool
    detail: str = ""


def evaluate_slos(observations: Dict[str, float], slos: Optional[List[SLO]] = None) -> List[SLOSample]:
    slos = slos or DEFAULT_SLOS
    results = []
    for s in slos:
        if s.name not in observations:
            results.append(SLOSample(s.name, float("nan"), False, "missing observation"))
            continue
        obs = float(observations[s.name])
        if s.higher_is_better:
            passed = obs >= s.target
            detail = f"{obs} >= {s.target} {s.unit}"
        else:
            passed = obs <= s.target
            detail = f"{obs} <= {s.target} {s.unit}"
        results.append(SLOSample(s.name, obs, passed, detail))
    return results


def all_passed(samples: List[SLOSample]) -> bool:
    return all(s.passed for s in samples)
