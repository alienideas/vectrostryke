"""
Phase 10 — confidential compute / enclave hooks (attestation gate for sensitive packs).
No real TEE required: models attestation evidence and policy gating.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass
class AttestationResult:
    ok: bool
    mode: str  # enclave | fallback | blocked
    reason: str
    quote_hash: Optional[str] = None


def simulate_quote(enclave_id: str, measurement: str) -> str:
    raw = f"{enclave_id}|{measurement}".encode()
    return hashlib.sha256(raw).hexdigest()


def verify_attestation(
    evidence: dict,
    *,
    expected_measurement: str,
    allow_fallback: bool = True,
) -> AttestationResult:
    if not evidence:
        if allow_fallback:
            return AttestationResult(True, "fallback", "no attestation; fallback allowed")
        return AttestationResult(False, "blocked", "attestation required")

    measurement = evidence.get("measurement") or ""
    if measurement != expected_measurement:
        if allow_fallback:
            return AttestationResult(False, "fallback", "measurement mismatch; fallback")
        return AttestationResult(False, "blocked", "measurement mismatch")

    enclave_id = evidence.get("enclave_id") or "unknown"
    quote = evidence.get("quote") or simulate_quote(enclave_id, measurement)
    expected_quote = simulate_quote(enclave_id, expected_measurement)
    if quote != expected_quote:
        return AttestationResult(False, "blocked", "quote invalid")

    return AttestationResult(True, "enclave", "attestation ok", quote_hash=quote)


def may_load_sensitive_pack(
    pack: dict,
    attestation: AttestationResult,
) -> Tuple[bool, str]:
    requires = bool((pack.get("hardening") or {}).get("requires_enclave")) or bool(
        (pack.get("attrs") or {}).get("requires_enclave")
    )
    if not requires:
        return True, "pack not enclave-gated"
    if attestation.mode == "enclave" and attestation.ok:
        return True, "enclave ok"
    return False, f"sensitive pack blocked: {attestation.reason}"
