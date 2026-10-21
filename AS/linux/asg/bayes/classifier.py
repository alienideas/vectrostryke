"""Naive Bayes spam/ham classifier (stdlib)."""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple

TOKEN_RE = re.compile(r"[a-z0-9]{3,}", re.I)


def tokenize(text: str) -> list:
    return TOKEN_RE.findall((text or "").lower())


class BayesModel:
    def __init__(self):
        self.spam_counts: Dict[str, int] = defaultdict(int)
        self.ham_counts: Dict[str, int] = defaultdict(int)
        self.spam_docs = 0
        self.ham_docs = 0

    def train(self, text: str, is_spam: bool) -> None:
        toks = set(tokenize(text))
        if is_spam:
            self.spam_docs += 1
            for t in toks:
                self.spam_counts[t] += 1
        else:
            self.ham_docs += 1
            for t in toks:
                self.ham_counts[t] += 1

    def score(self, text: str) -> Tuple[float, list]:
        toks = tokenize(text)
        if not toks or (self.spam_docs + self.ham_docs) == 0:
            return 0.5, []
        log_odds = 0.0
        contrib = []
        for t in set(toks):
            s = self.spam_counts.get(t, 0) + 1
            h = self.ham_counts.get(t, 0) + 1
            ratio = (s / (self.spam_docs + 2)) / (h / (self.ham_docs + 2))
            lo = math.log(ratio)
            log_odds += lo
            contrib.append((abs(lo), t, lo))
        try:
            p = 1 / (1 + math.exp(-log_odds / max(1, len(set(toks)))))
        except OverflowError:
            p = 1.0 if log_odds > 0 else 0.0
        top = [t for _, t, _ in sorted(contrib, reverse=True)[:5]]
        return p, top

    def save(self, path: Path) -> None:
        data = {
            "spam_counts": dict(self.spam_counts),
            "ham_counts": dict(self.ham_counts),
            "spam_docs": self.spam_docs,
            "ham_docs": self.ham_docs,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "BayesModel":
        m = cls()
        if not path.is_file():
            return m
        data = json.loads(path.read_text(encoding="utf-8"))
        m.spam_counts = defaultdict(int, data.get("spam_counts") or {})
        m.ham_counts = defaultdict(int, data.get("ham_counts") or {})
        m.spam_docs = int(data.get("spam_docs") or 0)
        m.ham_docs = int(data.get("ham_docs") or 0)
        return m
