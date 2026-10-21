"""Phase 6 pipeline: deception tripwires + MitM → Decision Core (prefer auto-contain)."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, List

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(PLATFORM / "decision_core" / "src"))
sys.path.insert(0, str(PLATFORM / "shared" / "contracts" / "src"))
sys.path.insert(0, str(PLATFORM / "phase4" / "src"))

from deception import CanaryRegistry, make_deception_event  # noqa: E402
from mitm import collect_mitm_indicators, make_mitm_event  # noqa: E402
from decision_core import process_event  # noqa: E402
from pack_signing import load_key, verify_pack  # noqa: E402
from validate import validate_policy_pack  # noqa: E402


def load_pack(path: Path, key_path: Path) -> dict:
    pack = json.loads(path.read_text(encoding="utf-8"))
    ok, msg = verify_pack(pack, load_key(key_path))
    if not ok:
        raise ValueError(msg)
    return validate_policy_pack(pack)


def handle_deception_event(event: dict, pack: dict) -> dict:
    result = process_event(event, pack)
    return {
        "event_id": event.get("id"),
        "type": event.get("type"),
        "vectors": result.vectors,
        "score": result.score,
        "mode": result.decision.mode,
        "reason": result.decision.reason,
        "actions": [a.get("kind") for a in (result.decision.actions or [])],
        "evidence_id": result.evidence.get("id") if result.evidence else None,
        "high_fidelity": True,
    }


def run_canary_file_check(registry: CanaryRegistry, pack: dict) -> List[dict]:
    return [handle_deception_event(e, pack) for e in registry.check_file_tripwires()]


def run_mitm_check(pack: dict, **kwargs) -> dict | None:
    inds = collect_mitm_indicators(**kwargs)
    if not inds:
        return None
    event = make_mitm_event(inds)
    result = process_event(event, pack)
    return {
        "event_id": event["id"],
        "mitm_indicators": inds,
        "vectors": result.vectors,
        "score": result.score,
        "mode": result.decision.mode,
        "reason": result.decision.reason,
        "evidence_id": result.evidence.get("id") if result.evidence else None,
    }
