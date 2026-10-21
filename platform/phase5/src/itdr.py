"""Phase 5 — ITDR signal builders: stale/dummy login, MFA fatigue, session risk."""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

SCHEMA = "1.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


def make_itdr_event(
    *,
    kind: str,
    user: str,
    device: Optional[str] = None,
    last_logon_age_sec: Optional[int] = None,
    attrs: Optional[dict] = None,
    technique_ids: Optional[list] = None,
) -> dict:
    base_attrs = {"itdr_kind": kind}
    if attrs:
        base_attrs.update(attrs)
    if kind == "stale_login":
        base_attrs["stale_login"] = True
    if kind == "dummy_login":
        base_attrs["dummy_login"] = True
        base_attrs["stale_login"] = True
    if kind == "mfa_fatigue":
        base_attrs["mfa_fatigue"] = True
    return {
        "schema_version": SCHEMA,
        "id": _id(),
        "ts": _now(),
        "type": "itdr",
        "subject": {"device": device or os.uname().nodename, "user": user},
        "object": {"itdr_kind": kind},
        "attrs": base_attrs,
        "geo_ip": None,
        "last_logon_age_sec": last_logon_age_sec,
        "mitm_indicators": [],
        "technique_ids": technique_ids or [],
    }


def is_stale_login(last_logon_age_sec: Optional[int], max_age_sec: int = 86400 * 90) -> bool:
    if last_logon_age_sec is None:
        return False
    return last_logon_age_sec > max_age_sec


def mfa_fatigue_detected(push_count: int, window_minutes: int = 10, threshold: int = 5) -> bool:
    return push_count >= threshold


def evaluate_auth_context(
    *,
    user: str,
    last_logon_age_sec: Optional[int] = None,
    mfa_push_count: int = 0,
    dummy_account: bool = False,
    max_stale_sec: int = 86400 * 90,
) -> list[dict]:
    events = []
    if dummy_account:
        events.append(make_itdr_event(kind="dummy_login", user=user, last_logon_age_sec=last_logon_age_sec))
    if is_stale_login(last_logon_age_sec, max_stale_sec):
        events.append(make_itdr_event(
            kind="stale_login", user=user, last_logon_age_sec=last_logon_age_sec, technique_ids=["T1078"],
        ))
    if mfa_fatigue_detected(mfa_push_count):
        events.append(make_itdr_event(
            kind="mfa_fatigue", user=user, attrs={"mfa_push_count": mfa_push_count}, technique_ids=["T1621"],
        ))
    return events
