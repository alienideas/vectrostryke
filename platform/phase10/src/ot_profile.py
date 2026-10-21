"""
Phase 10 — OT/ICS profile: protocol-aware Events + safety-first decision hints.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SCHEMA = "1.0.0"
PROTOCOLS = ("modbus", "dnp3", "opcua", "bacnet", "s7")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_ot_event(
    protocol: str,
    *,
    function_code: Optional[str] = None,
    anomaly: Optional[str] = None,
    safety_critical: bool = True,
    device: Optional[str] = None,
) -> dict:
    proto = protocol.lower()
    if proto not in PROTOCOLS:
        proto = "modbus"
    return {
        "schema_version": SCHEMA,
        "id": f"evt-{uuid.uuid4().hex[:12]}",
        "ts": _now(),
        "type": "ot",
        "subject": {"device": device or os.uname().nodename, "user": "ot-service"},
        "object": {"protocol": proto, "function_code": function_code, "anomaly": anomaly},
        "attrs": {
            "ot_profile": True,
            "protocol": proto,
            "safety_critical": safety_critical,
            "prefer_observe": safety_critical,
        },
        "geo_ip": None,
        "last_logon_age_sec": None,
        "mitm_indicators": [],
        "technique_ids": [],
    }


def safety_policy_for_ot(event: dict) -> dict:
    attrs = event.get("attrs") or {}
    if attrs.get("safety_critical") or event.get("type") == "ot":
        return {
            "allow_auto_kill_process": False,
            "prefer_modes": ["observe", "force_approval"],
            "allowed_actions": ["alert", "observe", "door_signal"],
            "reason": "ot_safety_first",
        }
    return {
        "allow_auto_kill_process": True,
        "prefer_modes": None,
        "allowed_actions": None,
        "reason": "non_ot",
    }


def filter_actions_for_ot(actions: List[dict], event: dict) -> List[dict]:
    policy = safety_policy_for_ot(event)
    allowed = policy.get("allowed_actions")
    if not allowed:
        return actions
    out = []
    for a in actions:
        kind = a.get("kind")
        if kind in allowed:
            out.append(a)
        elif kind in ("isolate_process", "kill_session"):
            b = dict(a)
            b["kind"] = "alert"
            b["result"] = a.get("result", "pending")
            b["ot_rewritten_from"] = kind
            out.append(b)
        else:
            out.append(a)
    return out
