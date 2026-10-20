"""Simple per-IP rate limiting."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple


class RateLimiter:
    def __init__(self, max_per_minute: int = 30):
        self.max_per_minute = max_per_minute
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def check(self, ip: str, now: float | None = None) -> Tuple[bool, str]:
        now = now or time.time()
        q = self._hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.max_per_minute:
            return True, f"rate_exceeded:{len(q)}/min"
        q.append(now)
        return False, "ok"
