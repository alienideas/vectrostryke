#!/usr/bin/env python3
"""Phase 7 tests — playbooks + OCSF export."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "decision_core" / "src"))
sys.path.insert(0, str(ROOT.parent / "shared" / "contracts" / "src"))
sys.path.insert(0, str(ROOT.parent / "phase4" / "src"))

from playbooks import expand_playbook, run_playbook, select_playbook  # noqa: E402
from ocsf_export import evidence_to_ocsf, export_evidence_file  # noqa: E402
from phase7_pipeline import load_pack, process_with_playbook  # noqa: E402

PACK = ROOT / "fixtures" / "pack-phase7.json"
KEY = ROOT.parent / "phase4" / "keys" / "dev.key"


def event_process():
    return {
        "schema_version": "1.0.0",
        "id": "evt-p7-1",
        "ts": "2026-10-20T12:00:00Z",
        "type": "process",
        "subject": {"device": "d1", "user": "u", "process": "pwsh"},
        "object": {},
        "attrs": {},
        "technique_ids": ["T1059.001"],
    }


class TestPlaybooks(unittest.TestCase):
    def setUp(self):
        self.pack = load_pack(PACK, KEY)

    def test_select_playbook_by_vector(self):
        pb = select_playbook(self.pack, ["lolbin"])
        self.assertIsNotNone(pb)
        self.assertEqual(pb["id"], "pb-lolbin")

    def test_expand_steps(self):
        pb = select_playbook(self.pack, ["ransomware_prep"])
        actions = expand_playbook(pb, event_process())
        kinds = [a["kind"] for a in actions]
        self.assertEqual(kinds, ["isolate_process", "quarantine_file", "alert"])

    def test_run_playbook_ordered(self):
        pb = select_playbook(self.pack, ["deception"])
        order = []

        def exec_track(actions, event):
            for a in actions:
                order.append(a["kind"])
            return [dict(a, result="success") for a in actions]

        summary = run_playbook(pb, event_process(), exec_track)
        self.assertEqual(summary["status"], "success")
        self.assertEqual(order, ["isolate_process", "kill_session", "block_network", "alert"])


class TestOCSF(unittest.TestCase):
    def test_evidence_to_ocsf_shape(self):
        ev = {
            "id": "evd-1",
            "ts": "2026-10-20T12:00:00Z",
            "vectors": ["lolbin"],
            "score": 75,
            "impact_class": False,
            "decision": "auto_act",
            "actions": [{"kind": "alert", "result": "success"}],
            "integrity": {"hash_alg": "sha256", "hash": "abc"},
            "export_labels": ["ocsf:security_finding"],
        }
        ocsf = evidence_to_ocsf(ev, event_process())
        self.assertEqual(ocsf["class_uid"], 2001)
        self.assertEqual(ocsf["finding_info"]["uid"], "evd-1")
        self.assertEqual(ocsf["risk_score"], 75)

    def test_export_file(self):
        tmp = Path(tempfile.mkdtemp())
        ev = {
            "id": "evd-2",
            "ts": "2026-10-20T12:00:00Z",
            "vectors": ["deception"],
            "score": 90,
            "impact_class": True,
            "decision": "auto_act",
            "actions": [],
            "integrity": {"hash_alg": "sha256", "hash": "x"},
        }
        path = export_evidence_file(ev, tmp)
        self.assertTrue(path.is_file())


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.pack = load_pack(PACK, KEY)
        self.tmp = Path(tempfile.mkdtemp())

    def test_auto_act_runs_playbook_and_exports(self):
        out = process_with_playbook(
            event_process(), self.pack, export_dir=self.tmp, auto_run_on_auto_act=True
        )
        self.assertEqual(out["playbook_id"], "pb-lolbin")
        self.assertIsNotNone(out["playbook_run"])
        self.assertEqual(out["ocsf"]["class_uid"], 2001)


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    raise SystemExit(0 if ok else 1)
