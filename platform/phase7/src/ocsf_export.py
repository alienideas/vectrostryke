"""Phase 7 — map Evidence / findings to OCSF-aligned security_finding JSON."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

OCSF_CLASS_UID = 2001
OCSF_CLASS_NAME = "Security Finding"
OCSF_CATEGORY_UID = 2
OCSF_CATEGORY_NAME = "Findings"


def _severity_id(score: float, impact_class: bool) -> int:
    if impact_class or score >= 90:
        return 5
    if score >= 70:
        return 4
    if score >= 40:
        return 3
    if score >= 20:
        return 2
    return 1


def evidence_to_ocsf(evidence: dict, event: Optional[dict] = None) -> dict:
    score = float(evidence.get("score") or 0)
    impact = bool(evidence.get("impact_class"))
    vectors = evidence.get("vectors") or []
    decision = evidence.get("decision") or "unknown"
    finding = {
        "class_uid": OCSF_CLASS_UID,
        "class_name": OCSF_CLASS_NAME,
        "category_uid": OCSF_CATEGORY_UID,
        "category_name": OCSF_CATEGORY_NAME,
        "activity_id": 1,
        "activity_name": "Create",
        "severity_id": _severity_id(score, impact),
        "status": "Success" if decision != "deny" else "Suppressed",
        "time": evidence.get("ts"),
        "finding_info": {
            "uid": evidence.get("id"),
            "title": f"VS finding: {', '.join(vectors) or 'unknown'}",
            "desc": f"decision={decision} score={score} impact_class={impact}",
            "types": vectors,
        },
        "risk_score": score,
        "metadata": {
            "product": {"name": "VectorStryke", "vendor_name": "VectorStryke"},
            "version": "1.0.0",
            "logged_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "labels": evidence.get("export_labels") or ["ocsf:security_finding"],
            "uid": evidence.get("id"),
        },
        "unmapped": {
            "vs_decision": decision,
            "vs_impact_class": impact,
            "vs_actions": evidence.get("actions") or [],
            "vs_integrity": evidence.get("integrity") or {},
            "vs_event_ids": evidence.get("event_ids") or [],
        },
    }
    if event:
        finding["unmapped"]["vs_event_type"] = event.get("type")
        finding["unmapped"]["vs_subject"] = event.get("subject")
        if event.get("technique_ids"):
            finding["finding_info"]["attacks"] = [
                {"technique": {"uid": t}} for t in event["technique_ids"]
            ]
    return finding


def export_evidence_file(evidence: dict, out_dir: Path, event: Optional[dict] = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ocsf = evidence_to_ocsf(evidence, event)
    path = out_dir / f"ocsf_{evidence.get('id', 'unknown')}.json"
    path.write_text(json.dumps(ocsf, indent=2), encoding="utf-8")
    return path


def export_batch(evidence_list: List[dict], out_dir: Path) -> List[Path]:
    return [export_evidence_file(ev, out_dir) for ev in evidence_list]
