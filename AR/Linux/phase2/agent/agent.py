#!/usr/bin/env python3
"""Phase 2 AR Linux agent — Collect → Decision Core → Act → Evidence."""
from __future__ import annotations

import json
import sys
from pathlib import Path

PHASE2_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = PHASE2_ROOT.parents[2]
sys.path.insert(0, str(ARTIFACTS / "platform" / "decision_core" / "src"))
sys.path.insert(0, str(ARTIFACTS / "platform" / "shared" / "contracts" / "src"))
sys.path.insert(0, str(ARTIFACTS / "platform" / "phase4" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect import collect_live_snapshot, collect_scenario  # noqa: E402
from act import ActExecutor  # noqa: E402
from decision_core import process_event  # noqa: E402
from pack_signing import load_key, sign_pack, verify_pack  # noqa: E402


class ARLinuxPhase2Agent:
    def __init__(self, pack_path: Path, evidence_dir: Path, quarantine_dir: Path, log_path: Path):
        self.pack_path = pack_path
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.executor = ActExecutor(quarantine_dir, log_path)
        self.pack = self._load_pack()

    def _load_pack(self) -> dict:
        if self.pack_path.is_file():
            pack = json.loads(self.pack_path.read_text(encoding="utf-8"))
            return pack
        # minimal offline pack
        return {
            "schema_version": "1.0.0",
            "id": "pack-default",
            "version": "1.0.0",
            "signature": {"alg": "hmac-sha256-dev", "value": "unsigned"},
            "rules": [
                {"id": "r-lolbin", "match": {"type": "process"}, "vector": "lolbin", "weight": 40},
                {"id": "r-file", "match": {"type": "file"}, "vector": "ransomware", "weight": 50},
            ],
            "thresholds": {"observe_max": 30, "auto_act_min": 70},
            "approval": {"impact_force": True, "timeout_sec": 60, "fallback": "observe"},
        }

    def _persist_evidence(self, evidence: dict) -> Path:
        path = self.evidence_dir / f"{evidence.get('id', 'evd')}.json"
        path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        return path

    def handle_event(self, event: dict, auto_approve_for_demo: bool = True) -> dict:
        result = process_event(event, self.pack)
        decision = result.decision
        action_results = []
        evidence = result.evidence
        if decision.mode == "auto_act" or (auto_approve_for_demo and decision.mode in ("approve", "force_approval")):
            action_results = self.executor.execute(decision.actions or [{"kind": "alert"}], event)
        path = self._persist_evidence(evidence) if evidence else None
        return {
            "event_id": event.get("id"),
            "vectors": result.vectors,
            "score": result.score,
            "mode": decision.mode,
            "reason": decision.reason,
            "actions": action_results or decision.actions,
            "evidence_id": evidence.get("id") if evidence else None,
            "evidence_path": str(path) if path else None,
        }

    def run_scenario(self, name: str, auto_approve_for_demo: bool = True) -> list:
        return [self.handle_event(e, auto_approve_for_demo) for e in collect_scenario(name)]

    def run_live_once(self) -> list:
        return [self.handle_event(e, auto_approve_for_demo=False) for e in collect_live_snapshot()]


def default_agent() -> ARLinuxPhase2Agent:
    root = PHASE2_ROOT
    return ARLinuxPhase2Agent(
        pack_path=root / "data" / "packs" / "pack-default.json",
        evidence_dir=root / "data" / "evidence",
        quarantine_dir=root / "data" / "quarantine",
        log_path=root / "data" / "act.log",
    )


def main(argv: list[str]) -> int:
    agent = default_agent()
    if len(argv) < 2:
        print("Usage: agent.py scenario <name>|live")
        return 2
    cmd = argv[1]
    if cmd == "scenario":
        name = argv[2] if len(argv) > 2 else "lolbin"
        for row in agent.run_scenario(name):
            print(json.dumps(row, indent=2))
        return 0
    if cmd == "live":
        for row in agent.run_live_once():
            print(json.dumps(row, indent=2))
        return 0
    print("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
