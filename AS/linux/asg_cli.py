#!/usr/bin/env python3
"""ASG CLI — inspect a message JSON file or run demo scenarios."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from asg.pipeline.engine import ASGEngine
from asg.adapters.rest import handle_message
from asg.bayes.classifier import BayesModel


def load_config(root: Path) -> dict:
    cfg = root / "config" / "asg.json"
    if cfg.is_file():
        return json.loads(cfg.read_text(encoding="utf-8"))
    return {
        "thresholds": {"accept_max": 40, "quarantine_max": 70},
        "weights": {
            "geo": 100, "spf_fail": 25, "dkim_fail": 20, "dmarc_fail": 25,
            "rbl_hit": 40, "phishing_heuristic": 35, "bayes_spam": 30, "rate_limit": 20,
        },
        "lists": {"rbl_enabled": True, "offline_demo": True},
        "behavioral": {"max_messages_per_minute": 30},
        "cidr_file": "data/cidr/blocklist.txt",
        "model_file": "data/models/bayes_model.json",
    }


DEMOS = {
    "clean": {
        "mail_from": "alice@company.com",
        "client_ip": "8.8.8.8",
        "headers": {"From": "alice@company.com", "Subject": "Lunch", "X-ASG-SPF": "pass", "X-ASG-DKIM": "pass", "X-ASG-DMARC": "pass"},
        "body": "Want to grab lunch tomorrow?",
    },
    "phish": {
        "mail_from": "ceo@evil.example",
        "client_ip": "203.0.113.50",
        "headers": {"From": "CEO <ceo@evil.example>", "Subject": "Urgent wire transfer", "X-ASG-SPF": "fail", "X-ASG-DKIM": "fail", "X-ASG-DMARC": "fail"},
        "body": "Urgent wire needed. Click here to login and verify your account password reset.",
    },
    "cidr": {
        "mail_from": "x@y.com",
        "client_ip": "198.51.100.20",
        "headers": {"Subject": "hi"},
        "body": "test",
    },
}


def main() -> int:
    p = argparse.ArgumentParser(description="VectorStryke ASG CLI")
    p.add_argument("cmd", choices=["demo", "inspect", "train-demo"])
    p.add_argument("arg", nargs="?", default="clean")
    args = p.parse_args()
    root = ROOT
    cfg = load_config(root)
    engine = ASGEngine(cfg, root)

    if args.cmd == "demo":
        name = args.arg if args.arg in DEMOS else "clean"
        print(json.dumps(handle_message(engine, DEMOS[name]), indent=2))
        return 0
    if args.cmd == "inspect":
        path = Path(args.arg)
        payload = json.loads(path.read_text())
        print(json.dumps(handle_message(engine, payload), indent=2))
        return 0
    if args.cmd == "train-demo":
        model = BayesModel()
        model.train("urgent wire transfer click here password", True)
        model.train("meeting notes agenda project update", False)
        dest = root / "data" / "models" / "bayes_model.json"
        model.save(dest)
        print(f"wrote {dest}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
