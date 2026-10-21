"""
Phase 10 — algorithm-agile pack signatures with dual-sign (classical + PQC-path).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ALG_CLASSICAL = "hmac-sha256-dev"
ALG_PQC_SIM = "hmac-sha3-256-pqc-sim"


def _canonical(pack: dict) -> bytes:
    body = deepcopy(pack)
    body.pop("signature", None)
    body.pop("signatures", None)
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_keypair_files(keys_dir: Path) -> Tuple[Path, Path]:
    keys_dir.mkdir(parents=True, exist_ok=True)
    classical = keys_dir / "classical.dev.key"
    pqc = keys_dir / "pqc_sim.dev.key"
    if not classical.is_file():
        classical.write_bytes(hashlib.sha256(b"VS-Phase10-Classical-NotForProd").digest())
    if not pqc.is_file():
        pqc.write_bytes(hashlib.sha256(b"VS-Phase10-PQCSim-NotForProd").digest())
    return classical, pqc


def load_key(path: Path) -> bytes:
    return path.read_bytes()


def _sign_one(body: bytes, key: bytes, alg: str) -> dict:
    if alg == ALG_CLASSICAL:
        val = hmac.new(key, body, hashlib.sha256).hexdigest()
    elif alg == ALG_PQC_SIM:
        val = hmac.new(key, body, hashlib.sha3_256).hexdigest()
    else:
        raise ValueError(f"unsupported alg: {alg}")
    return {"alg": alg, "value": val}


def sign_dual(pack: dict, classical_key: bytes, pqc_key: bytes) -> dict:
    out = deepcopy(pack)
    body = _canonical(out)
    out["signatures"] = [
        _sign_one(body, classical_key, ALG_CLASSICAL),
        _sign_one(body, pqc_key, ALG_PQC_SIM),
    ]
    out["signature"] = out["signatures"][0]
    return out


def verify_agile(
    pack: dict,
    classical_key: bytes,
    pqc_key: bytes,
    mode: str = "dual_required",
) -> Tuple[bool, str]:
    body = _canonical(pack)
    sigs: List[dict] = []
    if isinstance(pack.get("signatures"), list):
        sigs = list(pack["signatures"])
    elif isinstance(pack.get("signature"), dict):
        sigs = [pack["signature"]]

    def check(alg: str, key: bytes) -> bool:
        for s in sigs:
            if s.get("alg") != alg:
                continue
            expected = _sign_one(body, key, alg)["value"]
            if hmac.compare_digest(expected, (s.get("value") or "").strip()):
                return True
        return False

    classical_ok = check(ALG_CLASSICAL, classical_key)
    pqc_ok = check(ALG_PQC_SIM, pqc_key)

    if mode == "classical_only":
        return (True, "ok") if classical_ok else (False, "classical signature failed")
    if mode == "pqc_preferred":
        return (True, "ok") if pqc_ok else (False, "pqc signature failed")
    if mode == "dual_required":
        if classical_ok and pqc_ok:
            return True, "ok"
        missing = []
        if not classical_ok:
            missing.append("classical")
        if not pqc_ok:
            missing.append("pqc")
        return False, "missing/invalid: " + ",".join(missing)
    return False, f"unknown mode: {mode}"
