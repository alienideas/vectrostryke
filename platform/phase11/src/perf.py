"""Phase 11 — simple performance harness for Decision Core path."""
from __future__ import annotations

import statistics
import time
from typing import Callable, Dict, List


def time_calls(fn: Callable[[], None], iterations: int = 50) -> Dict[str, float]:
    samples: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples_sorted = sorted(samples)
    p95_idx = max(0, int(len(samples_sorted) * 0.95) - 1)
    return {
        "iterations": float(iterations),
        "mean_ms": statistics.mean(samples),
        "p50_ms": statistics.median(samples),
        "p95_ms": samples_sorted[p95_idx],
        "max_ms": max(samples),
        "min_ms": min(samples),
    }
