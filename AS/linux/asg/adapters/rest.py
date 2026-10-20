"""REST-style adapter: dict in → verdict out (for remote / test harness)."""
from __future__ import annotations

from typing import Any, Dict

from asg.pipeline.engine import ASGEngine, message_from_dict


def handle_message(engine: ASGEngine, payload: Dict[str, Any]) -> Dict[str, Any]:
    msg = message_from_dict(payload)
    verdict = engine.process(msg)
    return {
        "message_id": msg.message_id,
        "decision": verdict.decision,
        "score": verdict.score,
        "reasons": verdict.reasons,
        "factors": [{"name": f.name, "score": f.score, "detail": f.detail} for f in verdict.factors],
    }
