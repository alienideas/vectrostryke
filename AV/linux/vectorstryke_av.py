#!/usr/bin/env python3
"""VectorStryke AV – Linux OOP file scanner."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vs_av.models import VSConfig, VSOptions, VSRunContext
from vs_av.orchestrator import VSOrchestrator


def main() -> int:
    parser = argparse.ArgumentParser(description="VectorStryke AV – Linux scanner")
    parser.add_argument("--mode", choices=["FullScan", "QuickScan", "UpdateIndex"], default="QuickScan")
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    cfg = VSConfig()
    opts = VSOptions(mode=args.mode, threads=max(1, args.threads), quiet=args.quiet)
    ctx = VSRunContext(config=cfg, options=opts)
    orch = VSOrchestrator(ctx)
    try:
        orch.run()
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        ctx.cleanup()
        return 130
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        ctx.cleanup()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
