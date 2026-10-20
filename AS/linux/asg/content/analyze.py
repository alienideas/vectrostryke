"""Content / phishing heuristics."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

PHISH_PATTERNS = [
    r"urgent.{0,20}wire",
    r"verify your account",
    r"password.*(expire|reset)",
    r"click here.*(login|account)",
    r"bitcoin|cryptocurrency wallet",
]


def analyze_content(headers: Dict[str, str], body: str) -> Tuple[float, List[str]]:
    text = (body or "") + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
    text_l = text.lower()
    hits = []
    score = 0.0
    for pat in PHISH_PATTERNS:
        if re.search(pat, text_l, re.I):
            hits.append(f"heuristic:{pat[:24]}")
            score += 10.0
    urls = re.findall(r"https?://[^\s]+", text_l)
    if len(urls) >= 5:
        hits.append("url_density_high")
        score += 8.0
    frm = headers.get("From") or headers.get("from") or ""
    if "ceo" in frm.lower() and "@" in frm and "company.com" not in frm.lower():
        hits.append("display_name_suspect")
        score += 12.0
    return min(score, 50.0), hits
