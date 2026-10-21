#!/usr/bin/env python3
"""Offline operator CLI — Phase 3 surface (no control plane required)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PHASE3 = Path(__file__).resolve().parents[1]
PHASE2 = PHASE3.parent / "phase2"
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pipeline import OperatorPipeline  # noqa: E402
from store import OperatorStore  # noqa: E402


def data_root() -> Path:
    return PHASE3 / "data"


def pack_path() -> Path:
    return PHASE2 / "data" / "packs" / "pack-default.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VS AR Phase 3 Operator CLI (offline)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status")
    sub.add_parser("pending")
    p_show = sub.add_parser("show-pending")
    p_show.add_argument("pending_id")
    p_ap = sub.add_parser("approve")
    p_ap.add_argument("pending_id")
    p_dn = sub.add_parser("deny")
    p_dn.add_argument("pending_id")
    sub.add_parser("evidence")
    p_ev = sub.add_parser("show-evidence")
    p_ev.add_argument("evidence_id")
    p_sc = sub.add_parser("scenario")
    p_sc.add_argument("name", choices=["lolbin", "ransomware_prep", "benign_health", "deception"])
    sub.add_parser("export-status")

    args = parser.parse_args(argv)
    root = data_root()
    store = OperatorStore(root)
    pipe = OperatorPipeline(root, pack_path())

    if args.cmd == "status":
        print(json.dumps(store.status_summary(), indent=2))
        return 0
    if args.cmd == "pending":
        print(json.dumps(store.list_pending(), indent=2))
        return 0
    if args.cmd == "show-pending":
        rec = store.get_pending(args.pending_id)
        if not rec:
            print("not found", file=sys.stderr)
            return 1
        print(json.dumps(rec, indent=2))
        return 0
    if args.cmd == "approve":
        print(json.dumps(pipe.approve(args.pending_id), indent=2))
        return 0
    if args.cmd == "deny":
        print(json.dumps(pipe.deny(args.pending_id), indent=2))
        return 0
    if args.cmd == "evidence":
        print(json.dumps(store.list_evidence(20), indent=2))
        return 0
    if args.cmd == "show-evidence":
        ev = store.get_evidence(args.evidence_id)
        if not ev:
            print("not found", file=sys.stderr)
            return 1
        print(json.dumps(ev, indent=2))
        return 0
    if args.cmd == "scenario":
        print(json.dumps(pipe.run_scenario(args.name), indent=2))
        return 0
    if args.cmd == "export-status":
        out = PHASE3 / "static" / "status.json"
        store.write_status_json(out)
        print(str(out))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
