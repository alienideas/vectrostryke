"""Geo/CIDR early hard-reject."""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import List, Tuple


def load_cidrs(path: Path) -> List[ipaddress._BaseNetwork]:
    nets = []
    if not path.is_file():
        return nets
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return nets


def ip_blocked(ip: str, nets: List) -> Tuple[bool, str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "invalid_ip"
    for n in nets:
        if addr in n:
            return True, f"cidr_match:{n}"
    return False, "ok"
