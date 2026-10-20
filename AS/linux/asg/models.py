from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Message:
    message_id: str
    mail_from: str
    rcpt_to: List[str]
    client_ip: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    helo: str = ""
    raw_size: int = 0


@dataclass
class FactorResult:
    name: str
    score: float
    detail: str
    hard_reject: bool = False


@dataclass
class Verdict:
    decision: str  # accept | quarantine | reject
    score: float
    reasons: List[str]
    factors: List[FactorResult] = field(default_factory=list)
