"""Phase 10 pipeline: dual-sign verify → optional enclave gate → OT filter → privacy sync."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(PLATFORM / "decision_core" / "src"))
sys.path.insert(0, str(PLATFORM / "shared" / "contracts" / "src"))

from pqc_dual_sign import generate_keypair_files, load_key, sign_dual, verify_agile  # noqa: E402
from enclave import may_load_sensitive_pack, verify_attestation  # noqa: E402
from ot_profile import filter_actions_for_ot, make_ot_event, safety_policy_for_ot  # noqa: E402
from privacy_sync import redact_for_sync, split_local_and_sync  # noqa: E402
from decision_core import process_event  # noqa: E402
from validate import validate_policy_pack  # noqa: E402


def load_dual_pack(path: Path, keys_dir: Path, mode: str = "dual_required") -> dict:
    classical_p, pqc_p = generate_keypair_files(keys_dir)
    pack = json.loads(path.read_text(encoding="utf-8"))
    ok, msg = verify_agile(pack, load_key(classical_p), load_key(pqc_p), mode=mode)
    if not ok:
        raise ValueError(msg)
    return validate_policy_pack(pack)


def process_ot(event: dict, pack: dict) -> dict:
    result = process_event(event, pack)
    policy = safety_policy_for_ot(event)
    actions = filter_actions_for_ot(list(result.decision.actions or []), event)
    mode = result.decision.mode
    if policy.get("prefer_modes") and mode == "auto_act":
        if any(
            (a.get("kind") in ("isolate_process", "kill_session") and not a.get("ot_rewritten_from"))
            for a in (result.decision.actions or [])
        ):
            mode = "force_approval"
    return {
        "mode": mode,
        "vectors": result.vectors,
        "score": result.score,
        "actions": actions,
        "ot_policy": policy,
        "evidence": result.evidence,
        "sync_subset": redact_for_sync(result.evidence or {}, mode="minimize") if result.evidence else {},
    }
