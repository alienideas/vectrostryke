"""Phase 7 pipeline: select/run playbook + OCSF export after Decision Core."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(PLATFORM / "decision_core" / "src"))
sys.path.insert(0, str(PLATFORM / "shared" / "contracts" / "src"))
sys.path.insert(0, str(PLATFORM / "phase4" / "src"))

from playbooks import expand_playbook, run_playbook, select_playbook  # noqa: E402
from ocsf_export import evidence_to_ocsf, export_evidence_file  # noqa: E402
from decision_core import Decision, build_evidence, process_event  # noqa: E402
from pack_signing import load_key, verify_pack  # noqa: E402
from validate import validate_policy_pack  # noqa: E402


def load_pack(path: Path, key_path: Path) -> dict:
    pack = json.loads(path.read_text(encoding="utf-8"))
    ok, msg = verify_pack(pack, load_key(key_path))
    if not ok:
        raise ValueError(msg)
    return validate_policy_pack(pack)


def default_executor(actions: List[dict], event: dict) -> List[dict]:
    out = []
    for a in actions:
        r = dict(a)
        r["result"] = "success"
        out.append(r)
    return out


def process_with_playbook(
    event: dict,
    pack: dict,
    executor: Optional[Callable] = None,
    export_dir: Optional[Path] = None,
    auto_run_on_auto_act: bool = True,
) -> dict:
    result = process_event(event, pack)
    vectors = result.vectors
    pb = select_playbook(pack, vectors)
    playbook_run = None
    action_results = list(result.decision.actions or [])

    if pb and result.decision.mode == "auto_act" and auto_run_on_auto_act:
        playbook_run = run_playbook(pb, event, executor or default_executor)
        action_results = playbook_run["actions"]
        evidence = build_evidence(
            event, vectors, result.score, result.impact_class, result.decision, action_results
        )
    else:
        evidence = result.evidence
        if pb and result.decision.mode in ("approve", "force_approval"):
            action_results = expand_playbook(pb, event)

    ocsf_path = None
    ocsf_obj = None
    if evidence and export_dir is not None:
        ocsf_path = str(export_evidence_file(evidence, export_dir, event))
        ocsf_obj = evidence_to_ocsf(evidence, event)

    return {
        "vectors": vectors,
        "score": result.score,
        "mode": result.decision.mode,
        "playbook_id": pb.get("id") if pb else None,
        "playbook_run": playbook_run,
        "actions": action_results,
        "evidence": evidence,
        "ocsf_path": ocsf_path,
        "ocsf": ocsf_obj,
    }
