#!/usr/bin/env python3
"""Phase 3 operator surface tests — offline approve/deny + evidence."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PHASE3 = Path(__file__).resolve().parents[1]
PHASE2 = PHASE3.parent / "phase2"
sys.path.insert(0, str(PHASE3 / "operator"))
sys.path.insert(0, str(PHASE2 / "agent"))
sys.path.insert(0, str(PHASE3.parents[2] / "platform" / "decision_core" / "src"))
sys.path.insert(0, str(PHASE3.parents[2] / "platform" / "shared" / "contracts" / "src"))

from pipeline import OperatorPipeline  # noqa: E402
from store import OperatorStore  # noqa: E402


class TestPhase3(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vs-p3-"))
        self.pack = PHASE2 / "data" / "packs" / "pack-default.json"
        self.pipe = OperatorPipeline(self.tmp, self.pack)
        self.store = self.pipe.store

    def test_ransomware_stages_pending(self):
        rows = self.pipe.run_scenario("ransomware_prep")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].get("staged"))
        self.assertIn("pending_id", rows[0])
        pending = self.store.list_pending()
        self.assertGreaterEqual(len(pending), 1)

    def test_approve_executes_and_evidence(self):
        rows = self.pipe.run_scenario("ransomware_prep")
        pid = rows[0]["pending_id"]
        result = self.pipe.approve(pid)
        self.assertEqual(result["status"], "approved")
        self.assertIsNotNone(result.get("evidence_id"))
        self.assertEqual(len(self.store.list_pending()), 0)

    def test_deny_records_evidence(self):
        rows = self.pipe.run_scenario("ransomware_prep")
        pid = rows[0]["pending_id"]
        result = self.pipe.deny(pid)
        self.assertEqual(result["status"], "denied")
        ev = self.store.get_evidence(result["evidence_id"])
        self.assertEqual(ev["decision"], "deny")

    def test_benign_no_pending(self):
        rows = self.pipe.run_scenario("benign_health")
        self.assertFalse(rows[0].get("staged"))
        self.assertEqual(rows[0]["mode"], "observe")

    def test_status_summary(self):
        self.pipe.run_scenario("ransomware_prep")
        s = self.store.status_summary()
        self.assertTrue(s["offline"])
        self.assertFalse(s["control_plane"])
        self.assertGreaterEqual(s["pending_count"], 1)

    def test_export_status_json(self):
        self.pipe.run_scenario("ransomware_prep")
        out = self.tmp / "status.json"
        self.store.write_status_json(out)
        data = json.loads(out.read_text())
        self.assertIn("summary", data)
        self.assertIn("pending", data)


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    sys.exit(0 if ok else 1)
