"""Phase 2 Collect — produce Phase 0 Event objects from Linux signals / scenarios."""
from __future__ import annotations

import os
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator, List

SCHEMA = "1.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


def make_event(
    type_: str,
    subject: dict | None = None,
    object_: dict | None = None,
    attrs: dict | None = None,
    technique_ids: list | None = None,
) -> dict:
    return {
        "schema_version": SCHEMA,
        "id": _id(),
        "ts": _now(),
        "type": type_,
        "subject": subject or {"device": socket.gethostname(), "user": os.environ.get("USER", "unknown")},
        "object": object_ or {},
        "attrs": attrs or {},
        "geo_ip": None,
        "last_logon_age_sec": None,
        "mitm_indicators": [],
        "technique_ids": technique_ids or [],
    }


def collect_scenario(name: str) -> List[dict]:
    """Deterministic scenarios for E2E tests (no root required)."""
    host = socket.gethostname()
    if name == "lolbin":
        return [make_event(
            "process",
            subject={"device": host, "user": "alice", "process": "python3"},
            object_={"cmd": "encode-heavy-script"},
            attrs={"parent": "bash"},
            technique_ids=["T1059.001"],
        )]
    if name == "ransomware_prep":
        return [make_event(
            "file",
            subject={"device": host, "user": "bob"},
            object_={"path": "/tmp/vs_phase2_canary.doc", "op": "write_burst"},
            attrs={"entropy_hint": "high"},
        )]
    if name == "benign_health":
        return [make_event("health", subject={"device": host}, object_={"status": "ok"})]
    if name == "deception":
        return [make_event(
            "deception",
            subject={"device": host, "user": "mallory"},
            object_={"canary": "VS_CANARY_DOC.txt", "op": "read"},
        )]
    raise ValueError(f"unknown scenario: {name}")


def collect_live_snapshot() -> List[dict]:
    """Lightweight live signals (best-effort, no privileges required)."""
    events: List[dict] = []
    host = socket.gethostname()
    events.append(make_event(
        "process",
        subject={"device": host, "user": os.environ.get("USER", "unknown"), "process": "phase2-agent"},
        object_={"note": "heartbeat_process"},
        attrs={"source": "live_snapshot"},
    ))
    events.append(make_event(
        "health",
        subject={"device": host},
        object_={"agent": "ar-linux-phase2", "status": "running"},
    ))
    return events
