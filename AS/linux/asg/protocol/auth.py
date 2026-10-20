"""SPF / DKIM / DMARC evaluation (stdlib best-effort; offline-safe heuristics)."""
from __future__ import annotations

import re
from typing import Dict, Tuple


def _domain_of(addr: str) -> str:
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip(">")
    return addr.lower()


def check_spf(mail_from: str, client_ip: str, headers: Dict[str, str], offline_demo: bool = True) -> Tuple[str, str]:
    if offline_demo:
        forced = (headers.get("X-ASG-SPF") or headers.get("x-asg-spf") or "").lower()
        if forced in ("pass", "fail", "softfail", "none"):
            return forced, "header_override"
        return "none", "offline_no_dns"
    return "none", "dns_not_implemented"


def check_dkim(headers: Dict[str, str], offline_demo: bool = True) -> Tuple[str, str]:
    if offline_demo:
        forced = (headers.get("X-ASG-DKIM") or "").lower()
        if forced in ("pass", "fail", "none"):
            return forced, "header_override"
        if "DKIM-Signature" in headers or "dkim-signature" in {k.lower() for k in headers}:
            return "pass", "signature_present_offline"
        return "none", "no_signature"
    return "none", "dns_not_implemented"


def check_dmarc(mail_from: str, headers: Dict[str, str], spf: str, dkim: str, offline_demo: bool = True) -> Tuple[str, str]:
    if offline_demo:
        forced = (headers.get("X-ASG-DMARC") or "").lower()
        if forced in ("pass", "fail", "none"):
            return forced, "header_override"
        from_hdr = headers.get("From") or headers.get("from") or mail_from
        align = _domain_of(mail_from) == _domain_of(from_hdr) if from_hdr else False
        if (spf == "pass" or dkim == "pass") and align:
            return "pass", "aligned_auth"
        if spf == "fail" and dkim == "fail":
            return "fail", "auth_fail"
        return "none", "offline"
    return "none", "dns_not_implemented"
