#!/usr/bin/env python3
"""Phase 5 tests — ITDR + location → Decision Core."""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "decision_core" / "src"))
sys.path.insert(0, str(ROOT.parent / "shared" / "contracts" / "src"))
sys.path.insert(0, str(ROOT.parent / "phase4" / "src"))

from location import (  # noqa: E402
    LocationPoint,
    impossible_travel,
    outside_hours,
    geo_risk,
)
from itdr import evaluate_auth_context, is_stale_login, mfa_fatigue_detected  # noqa: E402
from phase5_pipeline import process_with_location, process_itdr_auth, load_signed_pack  # noqa: E402

PACK_PATH = ROOT / "fixtures" / "pack-phase5.json"
KEY_PATH = ROOT.parent / "phase4" / "keys" / "dev.key"


class TestLocation(unittest.TestCase):
    def test_impossible_travel_us_to_nl(self):
        t0 = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(hours=2)
        prev = LocationPoint(40.7, -74.0, t0, ip="1.1.1.1")
        curr = LocationPoint(52.3, 4.9, t1, ip="2.2.2.2")
        flag, detail = impossible_travel(prev, curr)
        self.assertTrue(flag)
        self.assertGreater(detail["implied_kmh"], 900)

    def test_possible_travel_short(self):
        t0 = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(hours=5)
        prev = LocationPoint(40.7, -74.0, t0)
        curr = LocationPoint(41.0, -73.5, t1)
        flag, _ = impossible_travel(prev, curr)
        self.assertFalse(flag)

    def test_outside_hours_night(self):
        night = datetime(2026, 10, 20, 3, 0, tzinfo=timezone.utc)
        flag, detail = outside_hours(night, 9, 18)
        self.assertTrue(flag)

    def test_inside_hours(self):
        day = datetime(2026, 10, 20, 14, 0, tzinfo=timezone.utc)
        flag, _ = outside_hours(day, 9, 18)
        self.assertFalse(flag)

    def test_geo_deny(self):
        flag, detail = geo_risk("RU", deny_list=["RU", "KP"])
        self.assertTrue(flag)
        self.assertEqual(detail["risk"], "deny_list")


class TestITDR(unittest.TestCase):
    def test_stale_login(self):
        self.assertTrue(is_stale_login(86400 * 100))
        self.assertFalse(is_stale_login(3600))

    def test_mfa_fatigue(self):
        self.assertTrue(mfa_fatigue_detected(8))
        self.assertFalse(mfa_fatigue_detected(2))

    def test_evaluate_auth_emits_events(self):
        evs = evaluate_auth_context(
            user="alice",
            last_logon_age_sec=86400 * 120,
            mfa_push_count=6,
            dummy_account=True,
        )
        kinds = {(e.get("attrs") or {}).get("itdr_kind") for e in evs}
        self.assertIn("stale_login", kinds)
        self.assertIn("mfa_fatigue", kinds)
        self.assertIn("dummy_login", kinds)


class TestPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = load_signed_pack(PACK_PATH, KEY_PATH)

    def test_impossible_travel_enriches_and_decides(self):
        t0 = datetime(2026, 10, 20, 8, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(hours=1)
        prev = LocationPoint(40.7, -74.0, t0)
        curr = LocationPoint(52.3, 4.9, t1)
        event = {
            "schema_version": "1.0.0",
            "id": "evt-loc-1",
            "ts": "2026-10-20T09:00:00Z",
            "type": "auth",
            "subject": {"device": "d1", "user": "alice"},
            "attrs": {},
        }
        out = process_with_location(
            event, self.pack, prev_loc=prev, curr_loc=curr, check_hours=False
        )
        self.assertTrue(out["attrs"].get("impossible_travel"))
        self.assertGreater(out["score"], 0)

    def test_outside_hours_sets_violation(self):
        event = {
            "schema_version": "1.0.0",
            "id": "evt-hrs",
            "ts": "2026-10-20T03:00:00Z",
            "type": "auth",
            "subject": {"user": "bob", "device": "d"},
            "attrs": {},
        }
        out = process_with_location(
            event, self.pack, check_hours=True, now_ts="2026-10-20T03:00:00Z"
        )
        self.assertTrue(out["attrs"].get("outside_hours"))
        self.assertIn(out["mode"], ("force_approval", "approve", "auto_act", "observe"))

    def test_itdr_stale_pipeline(self):
        outs = process_itdr_auth(self.pack, user="alice", last_logon_age_sec=86400 * 100)
        self.assertGreaterEqual(len(outs), 1)
        self.assertEqual(outs[0]["itdr_kind"], "stale_login")
        self.assertIn("credential_abuse", outs[0]["vectors"])

    def test_itdr_mfa_fatigue(self):
        outs = process_itdr_auth(self.pack, user="carol", mfa_push_count=10)
        self.assertTrue(any(o["itdr_kind"] == "mfa_fatigue" for o in outs))


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    raise SystemExit(0 if ok else 1)
