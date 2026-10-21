#!/usr/bin/env python3
"""Phase 11 tests — SLOs, canary release, performance harness."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "decision_core" / "src"))
sys.path.insert(0, str(ROOT.parent / "shared" / "contracts" / "src"))
sys.path.insert(0, str(ROOT.parent / "phase4" / "src"))

from slos import DEFAULT_SLOS, all_passed, evaluate_slos  # noqa: E402
from canary import CanaryController  # noqa: E402
from perf import time_calls  # noqa: E402


class TestSLOs(unittest.TestCase):
    def test_defaults_present(self):
        names = {s.name for s in DEFAULT_SLOS}
        self.assertIn("decision_latency_p95_ms", names)
        self.assertIn("evidence_write_success_pct", names)

    def test_evaluate_pass(self):
        obs = {
            "decision_latency_p95_ms": 150.0,
            "evidence_write_success_pct": 100.0,
            "pack_verify_load_sec": 1.0,
            "offline_protection_pct": 100.0,
            "fp_budget_per_pack": 2.0,
        }
        self.assertTrue(all_passed(evaluate_slos(obs)))

    def test_evaluate_fail_latency(self):
        obs = {
            "decision_latency_p95_ms": 5000.0,
            "evidence_write_success_pct": 100.0,
            "pack_verify_load_sec": 1.0,
            "offline_protection_pct": 100.0,
            "fp_budget_per_pack": 1.0,
        }
        samples = evaluate_slos(obs)
        self.assertFalse(all_passed(samples))


class TestCanary(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ctl = CanaryController(self.tmp / "canary_state.json")

    def test_start_and_promote(self):
        rel = self.ctl.start("rel-1", "pack-v2", cohort=["dev-a", "dev-b"])
        self.assertEqual(rel.percent, 5)
        self.ctl.record_metrics("rel-1", fp_rate_pct=1.0, error_rate_pct=0.1)
        rel = self.ctl.promote("rel-1")
        self.assertEqual(rel.percent, 25)
        self.assertTrue(self.ctl.device_in_canary("rel-1", "dev-a"))
        self.assertFalse(self.ctl.device_in_canary("rel-1", "dev-z"))

    def test_promote_blocked_on_fp(self):
        self.ctl.start("rel-2", "pack-v3", cohort=["d1"])
        self.ctl.record_metrics("rel-2", fp_rate_pct=20.0, error_rate_pct=0.0)
        with self.assertRaises(ValueError):
            self.ctl.promote("rel-2")
        self.assertEqual(self.ctl.releases["rel-2"].status, "paused")

    def test_rollback(self):
        self.ctl.start("rel-3", "agent-1.2", cohort=["d1"])
        self.ctl.record_metrics("rel-3", 0.5, 0.0)
        self.ctl.promote("rel-3")
        rel = self.ctl.rollback("rel-3")
        self.assertEqual(rel.status, "rolled_back")


class TestPerf(unittest.TestCase):
    def test_decision_core_latency_under_slo(self):
        from decision_core import process_event
        from pack_signing import load_key, sign_pack

        key = load_key(ROOT.parent / "phase4" / "keys" / "dev.key")
        pack = {
            "schema_version": "1.0.0",
            "id": "p11",
            "version": "1",
            "signature": {"alg": "hmac-sha256-dev", "value": "x"},
            "rules": [],
            "thresholds": {"observe_max": 30, "auto_act_min": 70},
            "approval": {"impact_force": False, "timeout_sec": 60, "fallback": "observe"},
        }
        pack = sign_pack(pack, key)
        event = {
            "schema_version": "1.0.0",
            "id": "e1",
            "ts": "2026-10-20T12:00:00Z",
            "type": "health",
            "subject": {"device": "d"},
        }

        def once():
            process_event(event, pack)

        stats = time_calls(once, iterations=30)
        self.assertLess(stats["p95_ms"], 2000.0)
        samples = evaluate_slos({
            "decision_latency_p95_ms": stats["p95_ms"],
            "evidence_write_success_pct": 100.0,
            "pack_verify_load_sec": 1.0,
            "offline_protection_pct": 100.0,
            "fp_budget_per_pack": 1.0,
        })
        self.assertTrue(all_passed(samples))


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    raise SystemExit(0 if ok else 1)
