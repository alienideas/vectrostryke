"""Phase 11 — canary release helper (staged rollout of packs/agents)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class CanaryRelease:
    release_id: str
    artifact: str
    stages: List[int] = field(default_factory=lambda: [5, 25, 50, 100])
    current_stage_idx: int = 0
    cohort: Set[str] = field(default_factory=set)
    status: str = "active"
    metrics: Dict[str, float] = field(default_factory=dict)
    created_ts: str = field(default_factory=_now)

    @property
    def percent(self) -> int:
        return self.stages[self.current_stage_idx]

    def to_dict(self) -> dict:
        return {
            "release_id": self.release_id,
            "artifact": self.artifact,
            "stages": self.stages,
            "current_stage_idx": self.current_stage_idx,
            "percent": self.percent,
            "cohort": sorted(self.cohort),
            "status": self.status,
            "metrics": self.metrics,
            "created_ts": self.created_ts,
        }


class CanaryController:
    def __init__(self, state_path: Path):
        self.state_path = state_path
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.releases: Dict[str, CanaryRelease] = {}
        if state_path.is_file():
            data = json.loads(state_path.read_text(encoding="utf-8"))
            for rid, rec in data.get("releases", {}).items():
                self.releases[rid] = CanaryRelease(
                    release_id=rec["release_id"],
                    artifact=rec["artifact"],
                    stages=rec.get("stages") or [5, 25, 50, 100],
                    current_stage_idx=rec.get("current_stage_idx", 0),
                    cohort=set(rec.get("cohort") or []),
                    status=rec.get("status", "active"),
                    metrics=rec.get("metrics") or {},
                    created_ts=rec.get("created_ts") or _now(),
                )

    def save(self) -> None:
        payload = {"releases": {k: v.to_dict() for k, v in self.releases.items()}}
        self.state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def start(self, release_id: str, artifact: str, cohort: List[str]) -> CanaryRelease:
        rel = CanaryRelease(release_id=release_id, artifact=artifact, cohort=set(cohort))
        self.releases[release_id] = rel
        self.save()
        return rel

    def record_metrics(self, release_id: str, fp_rate_pct: float, error_rate_pct: float) -> CanaryRelease:
        rel = self.releases[release_id]
        rel.metrics = {"fp_rate_pct": fp_rate_pct, "error_rate_pct": error_rate_pct}
        self.save()
        return rel

    def promote(self, release_id: str, max_fp_pct: float = 5.0, max_error_pct: float = 1.0) -> CanaryRelease:
        rel = self.releases[release_id]
        if rel.status != "active":
            raise ValueError(f"cannot promote status={rel.status}")
        fp = rel.metrics.get("fp_rate_pct", 0)
        err = rel.metrics.get("error_rate_pct", 0)
        if fp > max_fp_pct or err > max_error_pct:
            rel.status = "paused"
            self.save()
            raise ValueError(f"metrics gate failed fp={fp} err={err}")
        if rel.current_stage_idx >= len(rel.stages) - 1:
            rel.status = "promoted"
        else:
            rel.current_stage_idx += 1
        self.save()
        return rel

    def rollback(self, release_id: str) -> CanaryRelease:
        rel = self.releases[release_id]
        rel.status = "rolled_back"
        rel.current_stage_idx = 0
        self.save()
        return rel

    def device_in_canary(self, release_id: str, device_id: str) -> bool:
        rel = self.releases.get(release_id)
        if not rel or rel.status not in ("active", "promoted"):
            return False
        if rel.status == "promoted":
            return True
        return device_id in rel.cohort
