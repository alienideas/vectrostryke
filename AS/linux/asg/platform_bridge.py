"""Bridge ASG verdicts → VectorStryke Phase 0 Events + Decision Core."""
from __future__ import annotations

import socket
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from asg.models import Message, Verdict
from asg.pipeline.engine import ASGEngine

ARTIFACTS = Path(__file__).resolve().parents[3]
PLATFORM = ARTIFACTS / "platform"
sys.path.insert(0, str(PLATFORM / "decision_core" / "src"))
sys.path.insert(0, str(PLATFORM / "shared" / "contracts" / "src"))
sys.path.insert(0, str(PLATFORM / "phase4" / "src"))

from decision_core import process_event  # noqa: E402
from validate import validate_event  # noqa: E402


def __hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verdict_to_event(msg: Message, verdict: Verdict) -> dict:
    return {
        "schema_version": "1.0.0",
        "id": f"evt-{uuid.uuid4().hex[:12]}",
        "ts": _now(),
        "type": "mail",
        "subject": {"device": __hostname(), "user": msg.mail_from},
        "object": {
            "message_id": msg.message_id,
            "mail_from": msg.mail_from,
            "client_ip": msg.client_ip,
            "asg_decision": verdict.decision,
            "asg_score": verdict.score,
        },
        "attrs": {
            "module": "AS",
            "verdict": verdict.decision,
            "reasons": verdict.reasons,
        },
        "geo_ip": msg.client_ip,
        "technique_ids": ["T1566.002"] if verdict.decision in ("quarantine", "reject") else [],
    }


def process_with_platform(engine: ASGEngine, msg: Message, pack: dict) -> Dict[str, Any]:
    verdict = engine.process(msg)
    event = verdict_to_event(msg, verdict)
    validate_event(event)
    result = process_event(event, pack)
    return {
        "asg_verdict": verdict.decision,
        "asg_score": verdict.score,
        "asg_reasons": verdict.reasons,
        "event_id": event["id"],
        "platform_mode": result.decision.mode,
        "platform_vectors": result.vectors,
        "platform_score": result.score,
        "evidence_id": result.evidence.get("id") if result.evidence else None,
    }
