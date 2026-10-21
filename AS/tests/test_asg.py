#!/usr/bin/env python3
"""ASG unit + pipeline tests (stdlib)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

AS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AS_ROOT / "linux"))

from asg.pipeline.engine import ASGEngine, message_from_dict  # noqa: E402
from asg.adapters.rest import handle_message  # noqa: E402
from asg.bayes.classifier import BayesModel  # noqa: E402
from asg.protocol.auth import check_spf, check_dkim, check_dmarc  # noqa: E402


def cfg():
    return json.loads((AS_ROOT / "config" / "asg.json").read_text())


class TestASG(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        m = BayesModel()
        m.train("urgent wire transfer click here password login verify", True)
        m.train("project meeting agenda notes update team", False)
        m.save(AS_ROOT / "data" / "models" / "bayes_model.json")
        cls.engine = ASGEngine(cfg(), AS_ROOT)

    def test_cidr_hard_reject(self):
        out = handle_message(self.engine, {
            "mail_from": "a@b.com",
            "client_ip": "198.51.100.20",
            "headers": {},
            "body": "x",
        })
        self.assertEqual(out["decision"], "reject")

    def test_phish_high_score(self):
        out = handle_message(self.engine, {
            "mail_from": "ceo@evil.example",
            "client_ip": "203.0.113.50",
            "headers": {
                "From": "CEO <ceo@evil.example>",
                "Subject": "Urgent wire",
                "X-ASG-SPF": "fail",
                "X-ASG-DKIM": "fail",
                "X-ASG-DMARC": "fail",
            },
            "body": "Urgent wire. Click here to login and verify your account password.",
        })
        self.assertIn(out["decision"], ("quarantine", "reject"))
        self.assertGreater(out["score"], 40)

    def test_clean_accept(self):
        out = handle_message(self.engine, {
            "mail_from": "alice@company.com",
            "client_ip": "8.8.8.8",
            "headers": {
                "From": "alice@company.com",
                "Subject": "Notes",
                "X-ASG-SPF": "pass",
                "X-ASG-DKIM": "pass",
                "X-ASG-DMARC": "pass",
            },
            "body": "Project meeting agenda notes update team tomorrow.",
        })
        self.assertEqual(out["decision"], "accept")
        self.assertLessEqual(out["score"], 40)

    def test_spf_dkim_dmarc_headers(self):
        self.assertEqual(check_spf("a@b.com", "1.1.1.1", {"X-ASG-SPF": "fail"})[0], "fail")
        self.assertEqual(check_dkim({"X-ASG-DKIM": "pass"})[0], "pass")
        self.assertEqual(check_dmarc("a@b.com", {"From": "a@b.com"}, "pass", "pass")[0], "pass")

    def test_bayes_train_score(self):
        m = BayesModel()
        m.train("spam lottery winner claim prize", True)
        m.train("invoice attached for services", False)
        p, _ = m.score("lottery winner claim prize")
        self.assertGreater(p, 0.5)


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    raise SystemExit(0 if ok else 1)
