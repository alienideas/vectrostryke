#!/usr/bin/env python3
"""Phase 10 tests — PQC dual-sign, enclave, OT safety, privacy sync."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "decision_core" / "src"))
sys.path.insert(0, str(ROOT.parent / "shared" / "contracts" / "src"))

from pqc_dual_sign import (  # noqa: E402
    generate_keypair_files,
    load_key,
    sign_dual,
    verify_agile,
)
from enclave import may_load_sensitive_pack, simulate_quote, verify_attestation  # noqa: E402
from ot_profile import filter_actions_for_ot, make_ot_event, safety_policy_for_ot  # noqa: E402
from privacy_sync import redact_for_sync, split_local_and_sync  # noqa: E402
from phase10_pipeline import process_ot  # noqa: E402

KEYS = ROOT / "keys"
PACK = ROOT / "fixtures" / "pack-dual.json"
SENS = ROOT / "fixtures" / "pack-sensitive.json"


class TestPQC(unittest.TestCase):
    def setUp(self):
        self.c, self.p = generate_keypair_files(KEYS)
        self.ck = load_key(self.c)
        self.pk = load_key(self.p)
        self.pack = json.loads(PACK.read_text())

    def test_dual_required_ok(self):
        ok, msg = verify_agile(self.pack, self.ck, self.pk, mode="dual_required")
        self.assertTrue(ok, msg)

    def test_tamper_breaks_both(self):
        bad = dict(self.pack)
        bad["version"] = "9.9.9"
        ok, msg = verify_agile(bad, self.ck, self.pk, mode="dual_required")
        self.assertFalse(ok)

    def test_classical_only_mode(self):
        pack = dict(self.pack)
        pack["signatures"] = [s for s in pack["signatures"] if s["alg"] == "hmac-sha256-dev"]
        pack["signature"] = pack["signatures"][0]
        ok, _ = verify_agile(pack, self.ck, self.pk, mode="classical_only")
        self.assertTrue(ok)
        ok2, _ = verify_agile(pack, self.ck, self.pk, mode="dual_required")
        self.assertFalse(ok2)


class TestEnclave(unittest.TestCase):
    def test_attestation_ok(self):
        m = "meas-abc"
        eid = "enc-1"
        evidence = {"enclave_id": eid, "measurement": m, "quote": simulate_quote(eid, m)}
        att = verify_attestation(evidence, expected_measurement=m)
        self.assertTrue(att.ok)
        self.assertEqual(att.mode, "enclave")

    def test_sensitive_pack_blocked_without_enclave(self):
        pack = json.loads(SENS.read_text())
        att = verify_attestation({}, expected_measurement="x", allow_fallback=True)
        ok, reason = may_load_sensitive_pack(pack, att)
        self.assertFalse(ok)

    def test_sensitive_pack_allowed_with_enclave(self):
        pack = json.loads(SENS.read_text())
        m = "meas-ok"
        att = verify_attestation(
            {"enclave_id": "e1", "measurement": m, "quote": simulate_quote("e1", m)},
            expected_measurement=m,
        )
        ok, _ = may_load_sensitive_pack(pack, att)
        self.assertTrue(ok)


class TestOT(unittest.TestCase):
    def test_safety_policy(self):
        ev = make_ot_event("modbus", function_code="0x10", anomaly="write_burst")
        pol = safety_policy_for_ot(ev)
        self.assertFalse(pol["allow_auto_kill_process"])
        self.assertIn("observe", pol["prefer_modes"])

    def test_filter_rewrites_kill(self):
        ev = make_ot_event("dnp3", safety_critical=True)
        actions = [
            {"kind": "isolate_process", "result": "pending"},
            {"kind": "alert", "result": "pending"},
        ]
        out = filter_actions_for_ot(actions, ev)
        kinds = [a["kind"] for a in out]
        self.assertIn("alert", kinds)
        self.assertNotIn("isolate_process", kinds)

    def test_pipeline_ot(self):
        pack = json.loads(PACK.read_text())
        ev = make_ot_event("opcua", anomaly="unauthorized_write")
        out = process_ot(ev, pack)
        self.assertIn("ot_policy", out)
        self.assertFalse(out["ot_policy"]["allow_auto_kill_process"])


class TestPrivacy(unittest.TestCase):
    def test_minimize_strips_user(self):
        rec = {
            "id": "evd-1",
            "ts": "t",
            "score": 10,
            "decision": "observe",
            "subject": {"user": "alice"},
            "vectors": [],
            "impact_class": False,
            "integrity": {"hash": "x"},
        }
        sync = redact_for_sync(rec, mode="minimize")
        self.assertNotIn("subject", sync)
        self.assertEqual(sync.get("id"), "evd-1")
        self.assertEqual(sync["_privacy"]["full_forensics"], "local")

    def test_local_only(self):
        self.assertEqual(redact_for_sync({"id": "1"}, mode="local_only"), {})

    def test_split(self):
        ev = {"id": "e", "score": 1, "decision": "observe", "vectors": [], "impact_class": False}
        parts = split_local_and_sync(ev)
        self.assertEqual(parts["local"]["id"], "e")
        self.assertIn("_privacy", parts["sync"])


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    raise SystemExit(0 if ok else 1)
