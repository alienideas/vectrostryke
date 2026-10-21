"""Phase 6 — MitM / wireless anomaly indicators → Event enrichment."""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional

SCHEMA = "1.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


INDICATORS = {
    "tls_cert_mismatch": "TLS certificate does not match expected pin/hostname",
    "tls_downgrade": "Unexpected TLS version/cipher downgrade",
    "arp_anomaly": "ARP table conflict / gateway MAC change",
    "dns_spoof_suspicion": "DNS response IP not in allowlist / sudden shift",
    "imsi_catcher_hint": "Cellular environment anomaly (coarse hint only)",
    "proxy_injection": "Unexpected intercepting proxy detected",
}


def make_mitm_event(
    indicators: List[str],
    *,
    user: Optional[str] = None,
    device: Optional[str] = None,
    detail: Optional[dict] = None,
) -> dict:
    known = [i for i in indicators if i in INDICATORS]
    if not known:
        known = list(indicators)
    return {
        "schema_version": SCHEMA,
        "id": _id(),
        "ts": _now(),
        "type": "mitm",
        "subject": {
            "device": device or os.uname().nodename,
            "user": user or os.environ.get("USER", "unknown"),
        },
        "object": detail or {},
        "attrs": {"mitm_detected": True, "indicator_count": len(known)},
        "geo_ip": None,
        "last_logon_age_sec": None,
        "mitm_indicators": known,
        "technique_ids": ["T1557"],
    }


def evaluate_tls_pin(expected_fp: str, observed_fp: str) -> List[str]:
    if expected_fp and observed_fp and expected_fp.lower() != observed_fp.lower():
        return ["tls_cert_mismatch"]
    return []


def evaluate_gateway_mac(expected_mac: str, observed_mac: str) -> List[str]:
    if expected_mac and observed_mac and expected_mac.lower() != observed_mac.lower():
        return ["arp_anomaly"]
    return []


def evaluate_dns(expected_ips: List[str], observed_ip: str) -> List[str]:
    if expected_ips and observed_ip and observed_ip not in expected_ips:
        return ["dns_spoof_suspicion"]
    return []


def collect_mitm_indicators(
    *,
    expected_tls_fp: Optional[str] = None,
    observed_tls_fp: Optional[str] = None,
    expected_gw_mac: Optional[str] = None,
    observed_gw_mac: Optional[str] = None,
    expected_dns_ips: Optional[List[str]] = None,
    observed_dns_ip: Optional[str] = None,
    imsi_hint: bool = False,
) -> List[str]:
    inds: List[str] = []
    if expected_tls_fp and observed_tls_fp:
        inds.extend(evaluate_tls_pin(expected_tls_fp, observed_tls_fp))
    if expected_gw_mac and observed_gw_mac:
        inds.extend(evaluate_gateway_mac(expected_gw_mac, observed_gw_mac))
    if expected_dns_ips is not None and observed_dns_ip:
        inds.extend(evaluate_dns(expected_dns_ips, observed_dns_ip))
    if imsi_hint:
        inds.append("imsi_catcher_hint")
    return inds
