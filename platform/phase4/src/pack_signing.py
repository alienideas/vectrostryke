"""Phase 4 — policy pack signing & verification (stdlib HMAC-SHA256, dev-ready)."""
from __future__ import annotations

import hashlib
import hmac
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Tuple

ALG = "hmac-sha256-dev"


def generate_dev_key(path: Path) -> bytes:
    key = hashlib.sha256(b"VectorStryke-Phase4-DevKey-NotForProduction").digest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    return key


def load_key(path: Path) -> bytes:
    if not path.is_file():
        return generate_dev_key(path)
    return path.read_bytes()


def _canonical_pack_body(pack: dict) -> bytes:
    body = deepcopy(pack)
    body.pop("signature", None)
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_pack(pack: dict, key: bytes) -> dict:
    out = deepcopy(pack)
    sig = hmac.new(key, _canonical_pack_body(out), hashlib.sha256).hexdigest()
    out["signature"] = {"alg": ALG, "value": sig}
    return out


def verify_pack(pack: dict, key: bytes) -> Tuple[bool, str]:
    sig = pack.get("signature") or {}
    if not isinstance(sig, dict):
        return False, "missing signature object"
    alg = sig.get("alg") or ""
    value = (sig.get("value") or "").strip()
    if not value or value.lower() in ("unsigned", "none", "null"):
        return False, "unsigned pack"
    if alg != ALG:
        if alg and alg != ALG:
            return False, f"unsupported alg: {alg}"
    expected = hmac.new(key, _canonical_pack_body(pack), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, value):
        return False, "signature mismatch"
    return True, "ok"
