#!/usr/bin/env python3
"""
VectorStryke Phase 0 contract validators (stdlib only).
Validates Event, Action, Policy Pack, Evidence against schema rules in this file
(mirrors schemas/*.schema.json).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parents[1]
SCHEMAS_DIR = ROOT / "schemas"
FIXTURES_DIR = ROOT / "fixtures"

EVENT_TYPES = frozenset({
    "process", "file", "network", "auth", "media", "posture",
    "itdr", "deception", "ot", "mail", "mitm", "location", "health", "other",
})
ACTION_KINDS = frozenset({
    "isolate_process", "quarantine_file", "block_network", "kill_session",
    "harden_usb", "harden_drive", "door_signal", "alert", "playbook_step",
    "step_up_auth", "observe",
})
ACTION_RESULTS = frozenset({"success", "denied", "failed", "pending"})
DECISIONS = frozenset({"observe", "auto_act", "approve", "force_approval", "deny"})
APPROVAL_FALLBACKS = frozenset({"auto_act", "escalate", "observe"})


class ContractError(ValueError):
    """Raised when a payload fails contract validation."""


def _req(obj: dict, key: str) -> Any:
    if key not in obj:
        raise ContractError(f"missing required field: {key}")
    return obj[key]


def _str_nonempty(obj: dict, key: str) -> str:
    v = _req(obj, key)
    if not isinstance(v, str) or not v.strip():
        raise ContractError(f"{key} must be a non-empty string")
    return v


def _schema_version(obj: dict) -> None:
    v = _req(obj, "schema_version")
    if v != SCHEMA_VERSION:
        raise ContractError(f"schema_version must be {SCHEMA_VERSION!r}, got {v!r}")


def validate_event(obj: Any) -> dict:
    if not isinstance(obj, dict):
        raise ContractError("Event must be an object")
    _schema_version(obj)
    _str_nonempty(obj, "id")
    _str_nonempty(obj, "ts")
    t = _str_nonempty(obj, "type")
    if t not in EVENT_TYPES:
        raise ContractError(f"Event.type invalid: {t!r}")
    sub = _req(obj, "subject")
    if not isinstance(sub, dict):
        raise ContractError("Event.subject must be an object")
    if "last_logon_age_sec" in obj and obj["last_logon_age_sec"] is not None:
        if not isinstance(obj["last_logon_age_sec"], int) or obj["last_logon_age_sec"] < 0:
            raise ContractError("last_logon_age_sec must be null or non-negative int")
    for arr_key in ("mitm_indicators", "technique_ids"):
        if arr_key in obj and obj[arr_key] is not None:
            if not isinstance(obj[arr_key], list) or not all(isinstance(x, str) for x in obj[arr_key]):
                raise ContractError(f"{arr_key} must be a list of strings")
    return obj


def validate_action(obj: Any) -> dict:
    if not isinstance(obj, dict):
        raise ContractError("Action must be an object")
    _schema_version(obj)
    _str_nonempty(obj, "id")
    _str_nonempty(obj, "ts")
    kind = _str_nonempty(obj, "kind")
    if kind not in ACTION_KINDS:
        raise ContractError(f"Action.kind invalid: {kind!r}")
    result = _str_nonempty(obj, "result")
    if result not in ACTION_RESULTS:
        raise ContractError(f"Action.result invalid: {result!r}")
    if "target" in obj and obj["target"] is not None and not isinstance(obj["target"], dict):
        raise ContractError("Action.target must be an object")
    return obj


def validate_policy_pack(obj: Any) -> dict:
    if not isinstance(obj, dict):
        raise ContractError("Policy Pack must be an object")
    _schema_version(obj)
    _str_nonempty(obj, "id")
    _str_nonempty(obj, "version")
    sig = _req(obj, "signature")
    if not isinstance(sig, dict):
        raise ContractError("signature must be an object")
    alg = sig.get("alg")
    val = sig.get("value")
    if not isinstance(alg, str) or not alg.strip():
        raise ContractError("signature.alg must be a non-empty string")
    if not isinstance(val, str) or not val.strip():
        raise ContractError("signature.value must be a non-empty string")
    if val.strip().lower() in ("", "unsigned", "none", "null"):
        raise ContractError("unsigned or empty signature.value is not allowed")
    thr = _req(obj, "thresholds")
    if not isinstance(thr, dict):
        raise ContractError("thresholds must be an object")
    for k in ("observe_max", "auto_act_min"):
        if k not in thr or not isinstance(thr[k], (int, float)):
            raise ContractError(f"thresholds.{k} must be a number")
    ap = _req(obj, "approval")
    if not isinstance(ap, dict):
        raise ContractError("approval must be an object")
    if not isinstance(ap.get("impact_force"), bool):
        raise ContractError("approval.impact_force must be boolean")
    if not isinstance(ap.get("timeout_sec"), int) or ap["timeout_sec"] < 1:
        raise ContractError("approval.timeout_sec must be integer >= 1")
    fb = ap.get("fallback")
    if fb not in APPROVAL_FALLBACKS:
        raise ContractError(f"approval.fallback invalid: {fb!r}")
    if "rules" in obj and obj["rules"] is not None and not isinstance(obj["rules"], list):
        raise ContractError("rules must be an array")
    return obj


def validate_evidence(obj: Any) -> dict:
    if not isinstance(obj, dict):
        raise ContractError("Evidence must be an object")
    _schema_version(obj)
    _str_nonempty(obj, "id")
    _str_nonempty(obj, "ts")
    vectors = _req(obj, "vectors")
    if not isinstance(vectors, list) or not all(isinstance(x, str) for x in vectors):
        raise ContractError("vectors must be a list of strings")
    score = _req(obj, "score")
    if not isinstance(score, (int, float)) or score < 0 or score > 100:
        raise ContractError("score must be a number in [0, 100]")
    if not isinstance(_req(obj, "impact_class"), bool):
        raise ContractError("impact_class must be boolean")
    decision = _str_nonempty(obj, "decision")
    if decision not in DECISIONS:
        raise ContractError(f"decision invalid: {decision!r}")
    actions = _req(obj, "actions")
    if not isinstance(actions, list):
        raise ContractError("actions must be an array")
    integ = _req(obj, "integrity")
    if not isinstance(integ, dict):
        raise ContractError("integrity must be an object")
    if not isinstance(integ.get("hash_alg"), str) or not integ["hash_alg"].strip():
        raise ContractError("integrity.hash_alg required")
    if not isinstance(integ.get("hash"), str) or not integ["hash"].strip():
        raise ContractError("integrity.hash required")
    return obj


VALIDATORS = {
    "event": validate_event,
    "action": validate_action,
    "policy_pack": validate_policy_pack,
    "evidence": validate_evidence,
}


def validate(kind: str, obj: Any) -> dict:
    if kind not in VALIDATORS:
        raise ContractError(f"unknown contract kind: {kind}")
    return VALIDATORS[kind](obj)


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    import sys
    if len(sys.argv) < 3:
        print("Usage: validate.py <event|action|policy_pack|evidence> <file.json>")
        return 2
    kind, path = sys.argv[1], Path(sys.argv[2])
    try:
        validate(kind, load_json(path))
        print(f"OK {kind} {path}")
        return 0
    except (ContractError, json.JSONDecodeError, OSError) as e:
        print(f"FAIL {kind} {path}: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
