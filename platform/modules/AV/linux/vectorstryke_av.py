#!/usr/bin/env python3
"""VectorStryke AV Linux entry — see vs_av package."""
from __future__ import annotations
import argparse
from vs_av.orchestrator import run_scan

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", default="QuickScan", choices=["QuickScan", "FullScan", "UpdateIndex"])
    p.add_argument("--threads", type=int, default=2)
    args = p.parse_args()
    run_scan(mode=args.mode, threads=args.threads)

if __name__ == "__main__":
    main()
