"""Reputation / RBL (offline demo + optional live stub)."""
from __future__ import annotations

from typing import List, Tuple

DEMO_HITS = {"203.0.113.50", "198.51.100.10"}


def query_rbl(ip: str, offline_demo: bool = True, enabled: bool = True) -> Tuple[bool, str]:
    if not enabled:
        return False, "disabled"
    if offline_demo:
        if ip in DEMO_HITS:
            return True, "demo_rbl_hit"
        return False, "demo_clean"
    return False, "live_disabled"
