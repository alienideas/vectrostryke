"""Phase 3 pipeline: run events with staging to disk; approve/deny executes Act."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PHASE3 = Path(__file__).resolve().parents[1]
PHASE2 = PHASE3.parent / "phase2"
REPO = PHASE3.parents[2]

sys.path.insert(0, str(PHASE2 / "agent"))
sys.path.insert(0, str(REPO / "platform" / "decision_core" / "src"))
sys.path.insert(0, str(REPO / "platform" / "shared" / "contracts" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from decision_core import build_evidence, process_event  # noqa: E402
from collect import collect_scenario  # noqa: E402
from act import ActExecutor  # noqa: E402
from store import OperatorStore  # noqa: E402


class OperatorPipeline:
    def __init__(self, data_root: Path, pack_path: Path):
        self.store = OperatorStore(data_root)
        self.pack_path = pack_path
        self.actor = ActExecutor(data_root / "quarantine", data_root / "act.log")
        self.evidence_dir = self.store.evidence_dir

    def _pack(self) -> dict:
        return json.loads(self.pack_path.read_text(encoding="utf-8"))

    def ingest_event(self, event: dict) -> dict:
        pack = self._pack()
        result = process_event(event, pack, approvals=None)
        decision = result.decision
        out: dict[str, Any] = {
            "event_id": event.get("id"),
            "vectors": result.vectors,
            "score": result.score,
            "impact_class": result.impact_class,
            "mode": decision.mode,
            "reason": decision.reason,
        }

        if decision.mode in ("approve", "force_approval"):
            pending_id = decision.pending_id or f"pending-{event.get('id')}"
            record = {
                "pending_id": pending_id,
                "event": event,
                "vectors": result.vectors,
                "score": result.score,
                "impact_class": result.impact_class,
                "mode": decision.mode,
                "reason": decision.reason,
                "actions": decision.actions,
                "playbook_id": decision.playbook_id,
                "timeout_sec": decision.timeout_sec,
                "fallback": decision.fallback,
                "evidence_preview": result.evidence,
            }
            self.store.save_pending(record)
            if result.evidence:
                path = self.evidence_dir / f"{result.evidence['id']}.json"
                path.write_text(json.dumps(result.evidence, indent=2), encoding="utf-8")
                out["evidence_id"] = result.evidence["id"]
            out["pending_id"] = pending_id
            out["staged"] = True
            return out

        action_results = []
        if decision.mode == "auto_act" and decision.actions:
            action_results = self.actor.execute(decision.actions, event)
            evidence = build_evidence(
                event, result.vectors, result.score, result.impact_class, decision, action_results
            )
        else:
            evidence = result.evidence

        if evidence:
            path = self.evidence_dir / f"{evidence['id']}.json"
            path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            out["evidence_id"] = evidence["id"]
        out["actions"] = action_results
        out["staged"] = False
        return out

    def run_scenario(self, name: str) -> list:
        return [self.ingest_event(e) for e in collect_scenario(name)]

    def approve(self, pending_id: str) -> dict:
        rec = self.store.get_pending(pending_id)
        if not rec or rec.get("status") != "pending":
            raise FileNotFoundError(f"pending not found: {pending_id}")
        event = rec["event"]
        actions = rec.get("actions") or []
        action_results = self.actor.execute(actions, event) if actions else []
        from decision_core import Decision

        decision = Decision(
            mode="auto_act",
            vectors=rec.get("vectors") or [],
            score=float(rec.get("score") or 0),
            impact_class=bool(rec.get("impact_class")),
            actions=action_results,
            reason=(rec.get("reason") or "") + "|approved",
        )
        evidence = build_evidence(
            event, decision.vectors, decision.score, decision.impact_class, decision, action_results
        )
        path = self.evidence_dir / f"{evidence['id']}.json"
        path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        self.store.mark_resolved(pending_id, "approved", {"evidence_id": evidence["id"]})
        return {"pending_id": pending_id, "status": "approved", "evidence_id": evidence["id"], "actions": action_results}

    def deny(self, pending_id: str) -> dict:
        rec = self.store.get_pending(pending_id)
        if not rec or rec.get("status") != "pending":
            raise FileNotFoundError(f"pending not found: {pending_id}")
        event = rec["event"]
        from decision_core import Decision

        decision = Decision(
            mode="observe",
            vectors=rec.get("vectors") or [],
            score=float(rec.get("score") or 0),
            impact_class=bool(rec.get("impact_class")),
            actions=[],
            reason=(rec.get("reason") or "") + "|denied",
        )
        evidence = build_evidence(
            event, decision.vectors, decision.score, decision.impact_class, decision, []
        )
        evidence["decision"] = "deny"
        path = self.evidence_dir / f"{evidence['id']}.json"
        path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        self.store.mark_resolved(pending_id, "denied", {"evidence_id": evidence["id"]})
        return {"pending_id": pending_id, "status": "denied", "evidence_id": evidence["id"]}
