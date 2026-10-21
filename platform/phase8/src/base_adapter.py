"""Shared adapter helpers for Phase 8 modules on Phase 0 contracts."""
from __future__ import annotations

import os
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SCHEMA = "1.0.0"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id(prefix: str = "evt") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def make_event(
    type_: str,
    *,
    module: str,
    subject: Optional[dict] = None,
    object_: Optional[dict] = None,
    attrs: Optional[dict] = None,
    technique_ids: Optional[list] = None,
) -> dict:
    sub = subject or {"device": socket.gethostname(), "user": os.environ.get("USER", "unknown")}
    a = {"module": module}
    if attrs:
        a.update(attrs)
    return {
        "schema_version": SCHEMA,
        "id": new_id(),
        "ts": now_iso(),
        "type": type_,
        "subject": sub,
        "object": object_ or {},
        "attrs": a,
        "geo_ip": None,
        "last_logon_age_sec": None,
        "mitm_indicators": [],
        "technique_ids": technique_ids or [],
    }


def logical_act(actions: List[dict], event: dict, module: str) -> List[dict]:
    """Safe logical Act for all modules (no destructive OS calls)."""
    out = []
    for action in actions:
        r = dict(action)
        r["result"] = "success"
        r["module"] = module
        r["target"] = {**(action.get("target") or {}), "event_id": event.get("id"), "logical": True}
        out.append(r)
    return out
