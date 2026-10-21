#!/usr/bin/env python3
"""Phase 2 E2E: Collect → Decision Core → Act → Evidence on Linux."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PHASE2 = Path(__file__).resolve().parents[1]
REPO = PHASE2.parents[2]
sys.path.insert(0, str(PHASE2 / "agent"))
sys.path.insert(0, str(REPO / "platform" / "decision_core" / "src"))
sys.path.insert(0, str(REPO / "platform" / "shared" / "contracts" / "src"))

from agent import ARLinuxPhase2Agent  # noqa: E402
from validate import validate_evidence  # noqa: E402


class TestPhase2E2E(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vs-p2-"))
        self.pack = PHASE2 / "data" / "packs" / "pack-default.json"
        self.agent = ARLinuxPhase2Agent(
            pack_path=self.pack,
            evidence_dir=self.tmp / "evidence",
            quarantine_dir=self.tmp / "quarantine",
            log_path=self.tmp / "act.log",
        )

    def test_lolbin_scenario_acts_and_evidence(self):
        rows = self.agent.run_scenario("lolbin", auto_approve_for_demo=True)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertIn("lolbin", row["vectors"])
        self.assertIsNotNone(row["evidence_id"])
        ev_path = Path(row["evidence_path"])
        self.assertTrue(ev_path.is_file())
        evidence = json.loads(ev_path.read_text())
        validate_evidence(evidence)

    def test_ransomware_prep_force_or_act(self):
        rows = self.agent.run_scenario("ransomware_prep", auto_approve_for_demo=True)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertIn("ransomware_prep", row["vectors"])
        self.assertIsNotNone(row["evidence_path"])

    def test_benign_observe(self):
        rows = self.agent.run_scenario("benign_health", auto_approve_for_demo=False)
        row = rows[0]
        self.assertEqual(row["mode"], "observe")
        self.assertIsNotNone(row["evidence_id"])

    def test_deception_scenario(self):
        rows = self.agent.run_scenario("deception", auto_approve_for_demo=True)
        row = rows[0]
        self.assertIn("deception", row["vectors"])
        self.assertIsNotNone(row["evidence_path"])

    def test_live_snapshot_runs(self):
        rows = self.agent.run_live_once()
        self.assertGreaterEqual(len(rows), 1)
        for row in rows:
            self.assertIn("mode", row)


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    sys.exit(0 if ok else 1)
