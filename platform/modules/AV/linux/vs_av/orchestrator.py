"""Scan orchestrator."""
from __future__ import annotations
from .models import VSConfig, VSOptions, VSRunContext
from .scorer import VSScorer

def run_scan(mode: str = "QuickScan", threads: int = 2, quiet: bool = False) -> VSRunContext:
    cfg = VSConfig()
    opts = VSOptions(mode=mode, threads=threads, quiet=quiet)
    ctx = VSRunContext(config=cfg, options=opts)
    # Pipeline enumeration/scoring wired in full local tree; GitHub mirror is functional skeleton.
    if not quiet:
        print(f"VectorStryke AV Linux run {ctx.run_id} mode={mode}")
    return ctx
