#!/usr/bin/env python3
"""Phase 8 — AV, Core, BK, AS adapters on shared contracts."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "decision_core" / "src"))
sys.path.insert(0, str(ROOT.parent / "shared" / "contracts" / "src"))
sys.path.insert(0, str(ROOT.parent / "phase4" / "src"))
sys.path.insert(0, str(ROOT.parent / "phase7" / "src"))

from adapters import (  # noqa: E402
    ASAdapter,
    AVAdapter,
    BKAdapter,
    CoreAdapter,
    load_pack,
    run_all_modules,
)
from validate import validate_event, validate_evidence  # noqa: E402

PACK = ROOT / "fixtures" / "pack-phase8.json"
KEY = ROOT.parent / "phase4" / "keys" / "dev.key"


class TestPhase8Adapters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = load_pack(PACK, KEY)

    def test_av_malware(self):
        rows = AVAdapter().run_scenario("malware_hash", self.pack)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["module"], "AV")
        self.assertIn("malware", rows[0]["vectors"])
        if rows[0]["evidence"]:
            validate_evidence(rows[0]["evidence"])

    def test_av_clean_observe(self):
        rows = AVAdapter().run_scenario("clean", self.pack)
        self.assertEqual(rows[0]["mode"], "observe")

    def test_core_signature(self):
        rows = CoreAdapter().run_scenario("signature_hit", self.pack)
        self.assertEqual(rows[0]["module"], "Core")
        self.assertIn("malware", rows[0]["vectors"])

    def test_bk_integrity(self):
        rows = BKAdapter().run_scenario("integrity_fail", self.pack)
        self.assertEqual(rows[0]["module"], "BK")

    def test_as_phish(self):
        rows = ASAdapter().run_scenario("phish", self.pack)
        self.assertEqual(rows[0]["module"], "AS")
        self.assertIn("phishing", rows[0]["vectors"])

    def test_events_are_valid_contracts(self):
        for adapter_cls, scen in [
            (AVAdapter, "heuristic"),
            (CoreAdapter, "deep_scan"),
            (BKAdapter, "integrity_ok"),
            (ASAdapter, "spam"),
        ]:
            for e in adapter_cls().collect_scenario(scen):
                validate_event(e)

    def test_run_all_modules(self):
        out = run_all_modules(self.pack)
        self.assertEqual(set(out.keys()), {"AV", "Core", "BK", "AS"})


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    raise SystemExit(0 if ok else 1)
