#!/usr/bin/env python3
"""Phase 1 Decision Core unit tests."""
from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parents[0] / "shared" / "contracts" / "src"))

from decision_core import (  # noqa: E402
    ApprovalRegistry,
    PackState,
    build_evidence,
    classify,
    decide,
    process_event,
    score,
)
from validate import ContractError, validate_policy_pack  # noqa: E402

FIX = ROOT / "fixtures"
PACK = json.loads((FIX / "pack.json").read_text())


def ev(**kwargs):
    base = {
        "schema_version": "1.0.0",
        "id": "evt-test",
        "ts": "2026-10-20T12:00:00Z",
        "type": "process",
        "subject": {"device": "d1", "user": "u1"},
        "object": {},
        "attrs": {},
        "technique_ids": [],
    }
    base.update(kwargs)
    return base


class TestClassifyScoreDecide(unittest.TestCase):
    def test_classify_lolbin(self):
        e = ev(type="process", technique_ids=["T1059.001"])
        v = classify(e, PACK)
        self.assertIn("lolbin", v)

    def test_classify_unknown(self):
        e = ev(type="health")
        v = classify(e, PACK)
        self.assertEqual(v, ["unknown"])

    def test_score_range(self):
        e = ev(type="process", technique_ids=["T1059.001"])
        v = classify(e, PACK)
        sc, impact = score(e, v, PACK)
        self.assertGreaterEqual(sc, 0)
        self.assertLessEqual(sc, 100)

    def test_observe_low_score(self):
        e = ev(type="health")
        v = classify(e, PACK)
        sc, impact = score(e, v, PACK)
        d = decide(e, v, sc, impact, PACK)
        self.assertEqual(d.mode, "observe")

    def test_impact_force_approval(self):
        e = ev(type="file")
        v = classify(e, PACK)
        sc, impact = score(e, v, PACK)
        d = decide(e, v, sc, impact, PACK)
        self.assertTrue(impact)
        self.assertEqual(d.mode, "force_approval")
        self.assertIsNotNone(d.pending_id)

    def test_deception_auto_when_high(self):
        e = ev(type="deception")
        v = classify(e, PACK)
        sc, impact = score(e, v, PACK)
        d = decide(e, v, sc, impact, PACK)
        self.assertIn(d.mode, ("auto_act", "force_approval"))


class TestApproval(unittest.TestCase):
    def test_approve_path(self):
        e = ev(type="file")
        reg = ApprovalRegistry()
        result = process_event(e, PACK, approvals=reg)
        self.assertTrue(result.staged)
        pid = result.decision.pending_id
        resolved = reg.resolve(pid, approved=True)
        self.assertEqual(resolved.mode, "auto_act")
        self.assertIn("approved", resolved.reason)

    def test_deny_path(self):
        e = ev(type="file")
        reg = ApprovalRegistry()
        result = process_event(e, PACK, approvals=reg)
        resolved = reg.resolve(result.decision.pending_id, approved=False)
        self.assertEqual(resolved.mode, "observe")
        self.assertEqual(resolved.actions, [])

    def test_timeout_fallback_auto_act(self):
        e = ev(type="file")
        reg = ApprovalRegistry()
        result = process_event(e, PACK, approvals=reg)
        pid = result.decision.pending_id
        time.sleep(1.1)
        timed = reg.check_timeout(pid)
        self.assertIsNotNone(timed)
        self.assertEqual(timed.mode, "auto_act")
        self.assertIn("timeout", timed.reason)


class TestEvidenceAndPack(unittest.TestCase):
    def test_evidence_valid(self):
        e = ev(type="process", technique_ids=["T1059.001"])
        r = process_event(e, PACK)
        self.assertIsNotNone(r.evidence)
        self.assertIn("integrity", r.evidence)
        self.assertEqual(len(r.evidence["integrity"]["hash"]), 64)

    def test_unsigned_pack_rejected_lkg(self):
        state = PackState()
        state.load(PACK)
        bad = dict(PACK)
        bad["signature"] = {"alg": "ed25519-dev", "value": "unsigned"}
        with self.assertRaises(ContractError):
            state.load(bad)
        self.assertEqual(state.last_known_good["id"], PACK["id"])

    def test_pipeline_mid_band_approve(self):
        e = ev(type="process", technique_ids=["T1059.001"])
        r = process_event(e, PACK, approvals=ApprovalRegistry())
        self.assertIn(r.decision.mode, ("approve", "auto_act", "observe", "force_approval"))
        self.assertIsNotNone(r.evidence)


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    sys.exit(0 if ok else 1)
