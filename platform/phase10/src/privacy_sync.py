"""Phase 10 — privacy-preserving sync: local full forensics, minimal central subset."""
from __future__ import annotations

import copy
from typing import Any, Dict, Optional, Set

DEFAULT_REDACT = {
    "subject.user",
    "object.cmd",
    "object.path",
    "attrs.travel_detail",
    "unmapped",
}

DEFAULT_KEEP = {
    "schema_version",
    "id",
    "ts",
    "type",
    "vectors",
    "score",
    "impact_class",
    "decision",
    "integrity",
    "export_labels",
}


def _get_path(obj: dict, dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _set_path(obj: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = obj
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _del_path(obj: dict, dotted: str) -> None:
    parts = dotted.split(".")
    cur = obj
    for p in parts[:-1]:
        if not isinstance(cur, dict) or p not in cur:
            return
        cur = cur[p]
    if isinstance(cur, dict):
        cur.pop(parts[-1], None)


def redact_for_sync(
    record: dict,
    *,
    redact_fields: Optional[Set[str]] = None,
    keep_fields: Optional[Set[str]] = None,
    mode: str = "minimize",
) -> dict:
    if mode == "local_only":
        return {}
    redact_fields = redact_fields or DEFAULT_REDACT
    keep_fields = keep_fields or DEFAULT_KEEP
    if mode == "minimize":
        out: Dict[str, Any] = {}
        for k in keep_fields:
            if "." in k:
                v = _get_path(record, k)
                if v is not None:
                    _set_path(out, k, v)
            elif k in record:
                out[k] = copy.deepcopy(record[k])
        out["_privacy"] = {"mode": "minimize", "full_forensics": "local"}
        return out
    out = copy.deepcopy(record)
    for f in redact_fields:
        _del_path(out, f)
    out["_privacy"] = {"mode": "redact", "full_forensics": "local"}
    return out


def split_local_and_sync(evidence: dict, mode: str = "minimize") -> dict:
    return {"local": evidence, "sync": redact_for_sync(evidence, mode=mode)}
