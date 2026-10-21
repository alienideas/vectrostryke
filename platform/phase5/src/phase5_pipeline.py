"""Phase 5 pipeline: ITDR + location enrichment → Decision Core."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, List, Optional

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(PLATFORM / "decision_core" / "src"))
sys.path.insert(0, str(PLATFORM / "shared" / "contracts" / "src"))
sys.path.insert(0, str(PLATFORM / "phase4" / "src"))

from location import (  # noqa: E402
    LocationPoint,
    enrich_event_location,
    geo_risk,
    impossible_travel,
    outside_hours,
    parse_ts,
)
from itdr import evaluate_auth_context, make_itdr_event  # noqa: E402
from decision_core import process_event  # noqa: E402
from pack_signing import load_key, verify_pack, sign_pack  # noqa: E402
from validate import validate_policy_pack  # noqa: E402


def load_signed_pack(path: Path, key_path: Path) -> dict:
    pack = json.loads(path.read_text(encoding="utf-8"))
    key = load_key(key_path)
    ok, msg = verify_pack(pack, key)
    if not ok:
        raise ValueError(f"pack verify failed: {msg}")
    return validate_policy_pack(pack)


def process_with_location(
    event: dict,
    pack: dict,
    *,
    prev_loc: Optional[LocationPoint] = None,
    curr_loc: Optional[LocationPoint] = None,
    country: Optional[str] = None,
    allow_countries: Optional[list] = None,
    check_hours: bool = True,
    now_ts: Optional[str] = None,
) -> dict:
    from datetime import datetime, timezone

    enriched = dict(event)
    if prev_loc and curr_loc:
        flag, detail = impossible_travel(prev_loc, curr_loc)
        if flag:
            enriched = enrich_event_location(enriched, impossible=True, travel_detail=detail)
    if check_hours:
        now = parse_ts(now_ts) if now_ts else datetime.now(timezone.utc)
        start, end = 9, 18
        windows = pack.get("location_windows") or []
        if windows and isinstance(windows[0], dict):
            start = int(windows[0].get("start_hour", 9))
            end = int(windows[0].get("end_hour", 18))
        outside, hours_detail = outside_hours(now, start, end)
        if outside:
            enriched = enrich_event_location(enriched, outside=True, hours_detail=hours_detail)
    if country is not None:
        flag, detail = geo_risk(country, allow_list=allow_countries)
        if flag:
            enriched = enrich_event_location(enriched, geo_flag=True, geo_detail=detail)

    result = process_event(enriched, pack)
    return {
        "event": enriched,
        "vectors": result.vectors,
        "score": result.score,
        "impact_class": result.impact_class,
        "mode": result.decision.mode,
        "reason": result.decision.reason,
        "actions": result.decision.actions,
        "evidence": result.evidence,
        "attrs": enriched.get("attrs") or {},
    }


def process_itdr_auth(
    pack: dict,
    *,
    user: str,
    last_logon_age_sec: Optional[int] = None,
    mfa_push_count: int = 0,
    dummy_account: bool = False,
) -> List[dict]:
    events = evaluate_auth_context(
        user=user,
        last_logon_age_sec=last_logon_age_sec,
        mfa_push_count=mfa_push_count,
        dummy_account=dummy_account,
    )
    outs = []
    for ev in events:
        r = process_event(ev, pack)
        outs.append({
            "event_id": ev["id"],
            "itdr_kind": (ev.get("attrs") or {}).get("itdr_kind"),
            "vectors": r.vectors,
            "score": r.score,
            "mode": r.decision.mode,
            "reason": r.decision.reason,
            "evidence_id": r.evidence.get("id") if r.evidence else None,
        })
    return outs
