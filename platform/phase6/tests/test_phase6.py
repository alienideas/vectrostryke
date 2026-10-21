#!/usr/bin/env python3
"""Phase 6 tests — deception canaries + MitM → Decision Core."""
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

from deception import CanaryRegistry, make_deception_event  # noqa: E402
from mitm import collect_mitm_indicators  # noqa: E402
from phase6_pipeline import handle_deception_event, load_pack, run_canary_file_check, run_mitm_check  # noqa: E402

PACK = ROOT / "fixtures" / "pack-phase6.json"
KEY = ROOT.parent / "phase4" / "keys" / "dev.key"


class TestDeception(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.reg = CanaryRegistry(self.tmp)
        self.pack = load_pack(PACK, KEY)

    def test_deploy_and_trip_on_change(self):
        path = self.reg.deploy_file_canary("secrets_backup.docx")
        self.assertTrue(path.is_file())
        self.assertEqual(self.reg.check_file_tripwires(), [])
        path.write_text("TAMPERED", encoding="utf-8")
        trips = self.reg.check_file_tripwires()
        self.assertEqual(len(trips), 1)
        self.assertEqual(trips[0]["type"], "deception")

    def test_trip_on_delete(self):
        path = self.reg.deploy_file_canary("canary.txt")
        path.unlink()
        trips = self.reg.check_file_tripwires()
        self.assertEqual(len(trips), 1)

    def test_credential_and_host_events(self):
        self.reg.deploy_credential_canary("svc_backup_canary")
        self.reg.deploy_host_canary("honeypot.internal")
        ev1 = self.reg.trip_credential("svc_backup_canary")
        ev2 = self.reg.trip_host("honeypot.internal")
        self.assertEqual(ev1["type"], "deception")
        self.assertEqual(ev2["type"], "deception")

    def test_deception_prefers_auto_act(self):
        ev = make_deception_event(canary_type="file", name="x.doc", op="read")
        out = handle_deception_event(ev, self.pack)
        self.assertIn("deception", out["vectors"])
        self.assertIn(out["mode"], ("auto_act", "force_approval"))

    def test_pipeline_file_check(self):
        p = self.reg.deploy_file_canary("pay.docx")
        p.write_text("changed", encoding="utf-8")
        results = run_canary_file_check(self.reg, self.pack)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["high_fidelity"])


class TestMitM(unittest.TestCase):
    def setUp(self):
        self.pack = load_pack(PACK, KEY)

    def test_tls_mismatch_indicator(self):
        inds = collect_mitm_indicators(expected_tls_fp="aa:bb", observed_tls_fp="cc:dd")
        self.assertIn("tls_cert_mismatch", inds)

    def test_arp_and_dns(self):
        inds = collect_mitm_indicators(
            expected_gw_mac="11:22:33:44:55:66",
            observed_gw_mac="aa:bb:cc:dd:ee:ff",
            expected_dns_ips=["1.1.1.1"],
            observed_dns_ip="9.9.9.9",
        )
        self.assertIn("arp_anomaly", inds)
        self.assertIn("dns_spoof_suspicion", inds)

    def test_mitm_event_to_decision(self):
        out = run_mitm_check(self.pack, expected_tls_fp="a", observed_tls_fp="b", imsi_hint=True)
        self.assertIsNotNone(out)
        self.assertIn("network_mitm", out["vectors"])

    def test_no_indicators_returns_none(self):
        self.assertIsNone(run_mitm_check(self.pack))


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    raise SystemExit(0 if ok else 1)
