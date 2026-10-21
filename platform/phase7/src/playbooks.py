"""Phase 7 — SOAR-lite playbook runner (ordered Actions across kinds)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

SCHEMA = "1.0.0"

STEP_TO_KIND = {
    "isolate_process": "isolate_process",
    "quarantine_file": "quarantine_file",
    "block_network": "block_network",
    "kill_session": "kill_session",
    "harden_usb": "harden_usb",
    "harden_drive": "harden_drive",
    "door_signal": "door_signal",
    "alert": "alert",
    "step_up_auth": "step_up_auth",
    "observe": "observe",
    "playbook_step": "playbook_step",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uid(prefix: str = "act") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def select_playbook(pack: dict, vectors: List[str]) -> Optional[dict]:
    playbooks = pack.get("playbooks") or []
    vec_set = set(vectors or [])
    for pb in playbooks:
        if not isinstance(pb, dict):
            continue
        pb_vecs = set(pb.get("vectors") or [])
        if pb_vecs and pb_vecs & vec_set:
            return pb
    for pb in playbooks:
        if not isinstance(pb, dict):
            continue
        pid = str(pb.get("id") or "")
        if any(v in pid for v in vectors):
            return pb
    return playbooks[0] if playbooks else None


def expand_playbook(playbook: dict, event: Optional[dict] = None) -> List[dict]:
    steps = playbook.get("steps") or []
    actions = []
    for i, step in enumerate(steps):
        if isinstance(step, dict):
            kind = step.get("kind") or step.get("action") or "alert"
            target = step.get("target") or {}
        else:
            kind = STEP_TO_KIND.get(str(step), "alert")
            target = {}
        if event and not target:
            target = {"event_id": event.get("id"), "ref": (event.get("object") or {})}
        actions.append({
            "schema_version": SCHEMA,
            "id": _uid("act"),
            "ts": _now(),
            "kind": kind if kind in STEP_TO_KIND.values() else "alert",
            "target": target,
            "result": "pending",
            "evidence_id": None,
            "playbook_id": playbook.get("id"),
            "step_index": i,
        })
    return actions


def run_playbook(
    playbook: dict,
    event: dict,
    executor: Callable[[List[dict], dict], List[dict]],
    stop_on_failure: bool = False,
) -> dict:
    actions = expand_playbook(playbook, event)
    results: List[dict] = []
    status = "success"
    for batch in [[a] for a in actions]:
        step_results = executor(batch, event)
        results.extend(step_results)
        if stop_on_failure and any(r.get("result") == "failed" for r in step_results):
            status = "failed"
            break
    if any(r.get("result") == "failed" for r in results):
        status = "partial" if status != "failed" and any(r.get("result") == "success" for r in results) else status
        if all(r.get("result") == "failed" for r in results):
            status = "failed"
        elif any(r.get("result") == "failed" for r in results):
            status = "partial"
    return {
        "playbook_id": playbook.get("id"),
        "status": status if results else "empty",
        "steps_total": len(actions),
        "steps_run": len(results),
        "actions": results,
        "ts": _now(),
    }
