#!/usr/bin/env python3
"""Phase 9 — control plane multi-tenant isolation tests."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "phase4" / "src"))
sys.path.insert(0, str(ROOT.parent / "shared" / "contracts" / "src"))

from control_plane import ControlPlane  # noqa: E402
from pack_signing import load_key, sign_pack  # noqa: E402

KEY = ROOT.parent / "phase4" / "keys" / "dev.key"


def make_pack():
    pack = {
        "schema_version": "1.0.0",
        "id": "pack-phase9-tenant",
        "version": "0.1.0",
        "signature": {"alg": "hmac-sha256-dev", "value": "x"},
        "rules": [],
        "thresholds": {"observe_max": 30, "auto_act_min": 70},
        "approval": {"impact_force": True, "timeout_sec": 60, "fallback": "observe"},
    }
    return sign_pack(pack, load_key(KEY))


class TestPhase9(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cp = ControlPlane(self.tmp, KEY)
        self.pack = make_pack()

    def test_register_and_list(self):
        t = self.cp.tenants.create_tenant("Acme")
        tid = t["tenant_id"]
        dev = self.cp.register_device(tid, {"hostname": "host1", "os": "linux"})
        self.assertTrue(dev["device_id"].startswith("dev-"))
        self.assertEqual(len(self.cp.list_devices(tid)), 1)

    def test_publish_and_pull(self):
        t = self.cp.tenants.create_tenant("Acme")
        tid = t["tenant_id"]
        dev = self.cp.register_device(tid, {"hostname": "host1"})
        pub = self.cp.publish_pack(tid, self.pack)
        self.assertEqual(pub["pack_id"], "pack-phase9-tenant")
        pulled = self.cp.pull_pack_for_device(tid, dev["device_id"])
        self.assertEqual(pulled["id"], "pack-phase9-tenant")

    def test_reject_unsigned_pack(self):
        t = self.cp.tenants.create_tenant("Acme")
        bad = dict(self.pack)
        bad["signature"] = {"alg": "hmac-sha256-dev", "value": "unsigned"}
        with self.assertRaises(ValueError):
            self.cp.publish_pack(t["tenant_id"], bad)

    def test_event_isolation(self):
        a = self.cp.tenants.create_tenant("A")
        b = self.cp.tenants.create_tenant("B")
        self.cp.ingest_event(a["tenant_id"], {"id": "evt-a1", "type": "process"})
        self.cp.ingest_event(b["tenant_id"], {"id": "evt-b1", "type": "mail"})
        a_ids = {e["id"] for e in self.cp.list_events(a["tenant_id"])}
        self.assertIn("evt-a1", a_ids)
        self.assertNotIn("evt-b1", a_ids)

    def test_approval_routing(self):
        t = self.cp.tenants.create_tenant("Acme")
        tid = t["tenant_id"]
        self.cp.stage_approval(tid, {"pending_id": "p1", "reason": "impact"})
        self.assertEqual(len(self.cp.list_approvals(tid)), 1)
        self.cp.resolve_approval(tid, "p1", approved=True)
        self.assertEqual(len(self.cp.list_approvals(tid)), 0)

    def test_cross_tenant_denied(self):
        a = self.cp.tenants.create_tenant("A")
        b = self.cp.tenants.create_tenant("B")
        dev_b = self.cp.register_device(b["tenant_id"], {"hostname": "b-host"})
        self.cp.publish_pack(a["tenant_id"], self.pack)
        with self.assertRaises(PermissionError):
            self.cp.pull_pack_for_device(a["tenant_id"], dev_b["device_id"])


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    raise SystemExit(0 if ok else 1)
