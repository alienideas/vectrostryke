#!/usr/bin/env python3
"""
AR Linux Phase 2 agent — Collect → Decision Core → Act → Evidence

Wires Phase 0 contracts + Phase 1 decision_core on one OS (Linux).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, List, Optional

PHASE2_ROOT = Path(__file__).resolve().parents[1]
REPO = PHASE2_ROOT.parents[2]  # artifacts
sys.path.insert(0, str(REPO / "platform" / "decision_core" / "src"))
sys.path.insert(0, str(REPO / "platform" / "shared" / "contracts" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from decision_core import ApprovalRegistry, PackState, build_evidence, process_event  # noqa: E402
from validate import ContractError  # noqa: E402
from collect import collect_live_snapshot, collect_scenario  # noqa: E402
from act import ActExecutor  # noqa: E402


class ARLinuxPhase2Agent:
    def __init__(
        self,
        pack_path: Path,
        evidence_dir: Path,
        quarantine_dir: Path,
        log_path: Path,
    ):
        self.pack_path = pack_path
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.pack_state = PackState()
        self.approvals = ApprovalRegistry()
        self.actor = ActExecutor(quarantine_dir, log_path)
        self._load_pack()

    def _load_pack(self) -> None:
        data = json.loads(self.pack_path.read_text(encoding="utf-8"))
        try:
            self.pack_state.load(data)
        except ContractError:
            if self.pack_state.last_known_good is None:
                raise

    def _persist_evidence(self, evidence: dict) -> Path:
        path = self.evidence_dir / f"{evidence['id']}.json"
        path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        return path

    def handle_event(self, event: dict, auto_approve_for_demo: bool = False) -> dict:
        pack = self.pack_state.require_active()
        result = process_event(event, pack, approvals=self.approvals)
        decision = result.decision
        action_results: List[dict] = []

        if result.staged and auto_approve_for_demo and decision.pending_id:
            decision = self.approvals.resolve(decision.pending_id, approved=True)

        if decision.mode == "auto_act" and decision.actions:
            action_results = self.actor.execute(decision.actions, event)
            evidence = build_evidence(
                event, result.vectors, result.score, result.impact_class, decision, action_results
            )
        elif result.staged:
            evidence = result.evidence
            action_results = []
        else:
            evidence = result.evidence

        if evidence:
            path = self._persist_evidence(evidence)
        else:
            path = None

        return {
            "event_id": event.get("id"),
            "vectors": result.vectors,
            "score": result.score,
            "impact_class": result.impact_class,
            "mode": decision.mode,
            "reason": decision.reason,
            "staged": result.staged and decision.mode in ("approve", "force_approval"),
            "actions": action_results or decision.actions,
            "evidence_id": evidence.get("id") if evidence else None,
            "evidence_path": str(path) if path else None,
        }

    def run_scenario(self, name: str, auto_approve_for_demo: bool = True) -> List[dict]:
        outs = []
        for event in collect_scenario(name):
            outs.append(self.handle_event(event, auto_approve_for_demo=auto_approve_for_demo))
        return outs

    def run_live_once(self) -> List[dict]:
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
        print("Usage: agent.py scenario <lolbin|ransomware_prep|benign_health|deception>|live")
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
