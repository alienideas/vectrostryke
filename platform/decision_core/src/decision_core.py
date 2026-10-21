#!/usr/bin/env python3
"""
VectorStryke Phase 1 — Decision Core
CLASSIFY → SCORE → DECIDE (+ approval timeout) → Evidence

Language: Python (stdlib) for Phase 1 reference implementation.
This is NOT the C++ "Core" detection-engine module (that is /Core/).
Decision Core is the shared brain used by all agents later.

© VectorStryke
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

CONTRACTS_SRC = Path(__file__).resolve().parents[2] / "shared" / "contracts" / "src"
sys.path.insert(0, str(CONTRACTS_SRC))
from validate import (  # noqa: E402
    ContractError,
    validate_event,
    validate_evidence,
    validate_policy_pack,
)

SCHEMA_VERSION = "1.0.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class PackState:
    active: Optional[dict] = None
    last_known_good: Optional[dict] = None

    def load(self, pack: dict) -> dict:
        try:
            validated = validate_policy_pack(pack)
        except ContractError:
            raise
        self.last_known_good = deepcopy(validated)
        self.active = deepcopy(validated)
        return self.active

    def require_active(self) -> dict:
        if self.active is None:
            raise ContractError("no active policy pack loaded")
        return self.active


def classify(event: dict, pack: dict) -> list[str]:
    validate_event(event)
    vectors: list[str] = []
    rules = pack.get("rules") or []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        match = rule.get("match") or {}
        if "type" in match and match["type"] != event.get("type"):
            continue
        if "technique_ids" in match:
            want = set(match["technique_ids"] or [])
            have = set(event.get("technique_ids") or [])
            if want and not (want & have):
                continue
        attrs_match = match.get("attrs") or {}
        ev_attrs = event.get("attrs") or {}
        if any(ev_attrs.get(k) != v for k, v in attrs_match.items()):
            continue
        vec = rule.get("vector")
        if isinstance(vec, str) and vec and vec not in vectors:
            vectors.append(vec)
    if event.get("type") == "deception" and "deception" not in vectors:
        vectors.append("deception")
    if not vectors:
        vectors.append("unknown")
    return vectors


def score(event: dict, vectors: list[str], pack: dict) -> tuple[float, bool]:
    validate_event(event)
    rules = pack.get("rules") or []
    base = 0.0
    impact = False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        vec = rule.get("vector")
        if vec in vectors:
            w = rule.get("weight", 0)
            if isinstance(w, (int, float)):
                base += float(w)
            if rule.get("impact"):
                impact = True
    attrs = event.get("attrs") or {}
    if attrs.get("impossible_travel"):
        base += 25
    if attrs.get("stale_login"):
        base += 15
    if event.get("type") == "itdr":
        base += 20
    if "deception" in vectors or event.get("type") == "deception":
        base += 30
        impact = impact or bool(pack.get("approval", {}).get("impact_force"))
    base = max(0.0, min(100.0, base))
    if impact and pack.get("approval", {}).get("impact_force"):
        impact_class = True
    elif base >= 90 and pack.get("approval", {}).get("impact_force"):
        impact_class = True
    else:
        impact_class = bool(impact)
    return base, impact_class


@dataclass
class Decision:
    mode: str
    vectors: list[str]
    score: float
    impact_class: bool
    actions: list[dict] = field(default_factory=list)
    playbook_id: Optional[str] = None
    timeout_sec: Optional[int] = None
    fallback: Optional[str] = None
    pending_id: Optional[str] = None
    reason: str = ""


def _actions_for_vectors(vectors: list[str], pack: dict) -> tuple[list[dict], Optional[str]]:
    playbooks = pack.get("playbooks") or []
    for pb in playbooks:
        if not isinstance(pb, dict):
            continue
        pb_vecs = pb.get("vectors") or []
        if pb_vecs and not set(pb_vecs) & set(vectors):
            continue
        steps = pb.get("steps") or []
        actions = []
        for step in steps:
            if isinstance(step, str):
                actions.append({
                    "schema_version": SCHEMA_VERSION,
                    "id": _uid("act"),
                    "ts": _now_iso(),
                    "kind": step if step in (
                        "isolate_process", "quarantine_file", "block_network", "kill_session",
                        "harden_usb", "harden_drive", "door_signal", "alert", "playbook_step",
                        "step_up_auth", "observe",
                    ) else "alert",
                    "target": {},
                    "result": "pending",
                    "evidence_id": None,
                })
        if actions:
            return actions, pb.get("id")
    return [{
        "schema_version": SCHEMA_VERSION,
        "id": _uid("act"),
        "ts": _now_iso(),
        "kind": "alert",
        "target": {},
        "result": "pending",
        "evidence_id": None,
    }], None


def decide(event: dict, vectors: list[str], score_val: float, impact_class: bool, pack: dict) -> Decision:
    thr = pack.get("thresholds") or {}
    observe_max = float(thr.get("observe_max", 30))
    auto_min = float(thr.get("auto_act_min", 70))
    ap = pack.get("approval") or {}
    timeout_sec = int(ap.get("timeout_sec", 600))
    fallback = ap.get("fallback", "observe")
    actions, playbook_id = _actions_for_vectors(vectors, pack)

    if "deception" in vectors and score_val >= auto_min:
        return Decision(
            mode="auto_act", vectors=vectors, score=score_val, impact_class=impact_class,
            actions=actions, playbook_id=playbook_id, reason="deception_high_confidence",
        )
    if impact_class and ap.get("impact_force", True):
        return Decision(
            mode="force_approval", vectors=vectors, score=score_val, impact_class=True,
            actions=actions, playbook_id=playbook_id,
            timeout_sec=timeout_sec, fallback=fallback,
            pending_id=_uid("pending"), reason="impact_class",
        )
    attrs = event.get("attrs") or {}
    if attrs.get("location_violation") or attrs.get("outside_hours"):
        return Decision(
            mode="force_approval", vectors=vectors, score=score_val, impact_class=impact_class,
            actions=actions, playbook_id=playbook_id,
            timeout_sec=timeout_sec, fallback=fallback,
            pending_id=_uid("pending"), reason="location_or_hours",
        )
    if attrs.get("stale_login") or event.get("type") == "itdr":
        if score_val >= auto_min:
            return Decision(
                mode="force_approval", vectors=vectors, score=score_val, impact_class=impact_class,
                actions=actions, playbook_id=playbook_id,
                timeout_sec=timeout_sec, fallback=fallback,
                pending_id=_uid("pending"), reason="itdr_or_stale",
            )
    if score_val <= observe_max:
        return Decision(
            mode="observe", vectors=vectors, score=score_val, impact_class=impact_class,
            actions=[], playbook_id=None, reason="below_observe_max",
        )
    if score_val >= auto_min and not impact_class:
        return Decision(
            mode="auto_act", vectors=vectors, score=score_val, impact_class=impact_class,
            actions=actions, playbook_id=playbook_id, reason="above_auto_act_min",
        )
    return Decision(
        mode="approve", vectors=vectors, score=score_val, impact_class=impact_class,
        actions=actions, playbook_id=playbook_id,
        timeout_sec=timeout_sec, fallback=fallback,
        pending_id=_uid("pending"), reason="mid_band_approval",
    )


@dataclass
class PendingApproval:
    decision: Decision
    created_monotonic: float


class ApprovalRegistry:
    def __init__(self) -> None:
        self._pending: dict[str, PendingApproval] = {}

    def stage(self, decision: Decision) -> str:
        if not decision.pending_id:
            decision.pending_id = _uid("pending")
        self._pending[decision.pending_id] = PendingApproval(decision, time.monotonic())
        return decision.pending_id

    def resolve(self, pending_id: str, approved: bool) -> Decision:
        item = self._pending.pop(pending_id, None)
        if item is None:
            raise ContractError(f"unknown pending_id: {pending_id}")
        d = item.decision
        if approved:
            d.mode = "auto_act"
            d.reason = (d.reason or "") + "|approved"
            for a in d.actions:
                a["result"] = "pending"
        else:
            d.mode = "observe"
            d.actions = []
            d.reason = (d.reason or "") + "|denied"
        return d

    def check_timeout(self, pending_id: str) -> Optional[Decision]:
        item = self._pending.get(pending_id)
        if item is None:
            return None
        timeout = item.decision.timeout_sec or 600
        if time.monotonic() - item.created_monotonic < timeout:
            return None
        self._pending.pop(pending_id, None)
        d = item.decision
        fb = d.fallback or "observe"
        if fb == "auto_act":
            d.mode = "auto_act"
            d.reason = (d.reason or "") + "|timeout_auto_act"
        elif fb == "escalate":
            d.mode = "force_approval"
            d.reason = (d.reason or "") + "|timeout_escalate"
        else:
            d.mode = "observe"
            d.actions = []
            d.reason = (d.reason or "") + "|timeout_observe"
        return d


def build_evidence(
    event: dict,
    vectors: list[str],
    score_val: float,
    impact_class: bool,
    decision: Decision,
    action_results: Optional[list[dict]] = None,
) -> dict:
    actions = action_results if action_results is not None else decision.actions
    body = {
        "schema_version": SCHEMA_VERSION,
        "id": _uid("evd"),
        "ts": _now_iso(),
        "vectors": list(vectors),
        "score": float(score_val),
        "impact_class": bool(impact_class),
        "decision": "observe",
        "actions": actions,
        "event_ids": [event.get("id", "")],
        "export_labels": ["ocsf:security_finding"],
    }
    mode = decision.mode
    if "|denied" in (decision.reason or ""):
        body["decision"] = "deny"
    elif mode in ("auto_act",):
        body["decision"] = "auto_act"
    elif mode in ("approve", "force_approval"):
        body["decision"] = "force_approval" if mode == "force_approval" else "approve"
    else:
        body["decision"] = "observe"
    canon = json.dumps(
        {k: body[k] for k in ("id", "ts", "vectors", "score", "impact_class", "decision", "actions")},
        sort_keys=True, separators=(",", ":"),
    )
    body["integrity"] = {
        "hash_alg": "sha256",
        "hash": hashlib.sha256(canon.encode("utf-8")).hexdigest(),
    }
    return validate_evidence(body)


@dataclass
class ProcessResult:
    event: dict
    vectors: list[str]
    score: float
    impact_class: bool
    decision: Decision
    evidence: Optional[dict]
    staged: bool = False


def process_event(
    event: dict,
    pack: dict,
    approvals: Optional[ApprovalRegistry] = None,
    write_evidence_on_stage: bool = True,
) -> ProcessResult:
    validate_event(event)
    pack = validate_policy_pack(pack)
    vectors = classify(event, pack)
    sc, impact = score(event, vectors, pack)
    decision = decide(event, vectors, sc, impact, pack)

    staged = False
    if decision.mode in ("approve", "force_approval") and approvals is not None:
        approvals.stage(decision)
        staged = True

    evidence = None
    if write_evidence_on_stage or not staged:
        evidence = build_evidence(event, vectors, sc, impact, decision)
    elif staged and write_evidence_on_stage:
        evidence = build_evidence(event, vectors, sc, impact, decision)

    if staged and evidence is None:
        evidence = build_evidence(event, vectors, sc, impact, decision)

    return ProcessResult(
        event=event,
        vectors=vectors,
        score=sc,
        impact_class=impact,
        decision=decision,
        evidence=evidence,
        staged=staged,
    )
