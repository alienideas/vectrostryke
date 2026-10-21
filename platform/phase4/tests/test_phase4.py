#!/usr/bin/env python3
"""Phase 4 tests: signed packs, evidence integrity, self-protect, sync."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parents[0] / "shared" / "contracts" / "src"))
sys.path.insert(0, str(ROOT.parents[0] / "decision_core" / "src"))

from pack_signing import generate_dev_key, load_key, sign_pack, verify_pack  # noqa: E402
from evidence_store import EvidenceStore  # noqa: E402
from self_protect import build_manifest, verify_manifest, save_manifest, load_manifest  # noqa: E402
from sync import SyncService  # noqa: E402
from decision_core import process_event  # noqa: E402
from validate import validate_policy_pack  # noqa: E402


def sample_pack() -> dict:
    return {
        "schema_version": "1.0.0",
        "id": "pack-p4",
        "version": "0.2.0",
        "signature": {"alg": "hmac-sha256-dev", "value": "placeholder"},
        "rules": [{"id": "r1", "match": {"type": "process"}, "vector": "lolbin", "weight": 40}],
        "thresholds": {"observe_max": 30, "auto_act_min": 70},
        "approval": {"impact_force": True, "timeout_sec": 60, "fallback": "observe"},
    }


class TestPackSigning(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.key = generate_dev_key(self.tmp / "dev.key")

    def test_sign_and_verify(self):
        pack = sign_pack(sample_pack(), self.key)
        ok, msg = verify_pack(pack, self.key)
        self.assertTrue(ok, msg)
        validate_policy_pack(pack)

    def test_tamper_detected(self):
        pack = sign_pack(sample_pack(), self.key)
        pack["version"] = "9.9.9"
        ok, msg = verify_pack(pack, self.key)
        self.assertFalse(ok)
        self.assertIn("mismatch", msg)

    def test_unsigned_rejected(self):
        pack = sample_pack()
        pack["signature"] = {"alg": "hmac-sha256-dev", "value": "unsigned"}
        ok, msg = verify_pack(pack, self.key)
        self.assertFalse(ok)


class TestEvidenceStore(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = EvidenceStore(self.tmp)

    def test_write_verify(self):
        pack = sample_pack()
        key = generate_dev_key(self.tmp / "k")
        pack = sign_pack(pack, key)
        event = {
            "schema_version": "1.0.0",
            "id": "evt-1",
            "ts": "2026-10-20T12:00:00Z",
            "type": "health",
            "subject": {"device": "d"},
        }
        result = process_event(event, pack)
        self.assertIsNotNone(result.evidence)
        path = self.store.write(result.evidence)
        self.assertTrue(path.is_file())
        loaded = self.store.read(result.evidence["id"])
        ok, msg = self.store.verify(loaded)
        self.assertTrue(ok, msg)

    def test_integrity_mismatch(self):
        ev = {
            "id": "evd-x",
            "ts": "t",
            "vectors": [],
            "score": 1,
            "impact_class": False,
            "decision": "observe",
            "actions": [],
            "integrity": {"hash_alg": "sha256", "hash": "deadbeef"},
        }
        ok, msg = self.store.verify(ev)
        self.assertFalse(ok)


class TestSelfProtect(unittest.TestCase):
    def test_manifest_healthy_then_degraded(self):
        tmp = Path(tempfile.mkdtemp())
        f = tmp / "agent.py"
        f.write_text("print('ok')\n", encoding="utf-8")
        man = build_manifest([f], tmp)
        save_manifest(tmp / "manifest.json", man)
        status, problems = verify_manifest(load_manifest(tmp / "manifest.json"), tmp)
        self.assertEqual(status, "healthy")
        f.write_text("print('tampered')\n", encoding="utf-8")
        status, problems = verify_manifest(load_manifest(tmp / "manifest.json"), tmp)
        self.assertEqual(status, "degraded")
        self.assertTrue(any("tampered" in p for p in problems))


class TestSync(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.key_path = self.tmp / "dev.key"
        self.key = generate_dev_key(self.key_path)
        self.store = EvidenceStore(self.tmp / "evidence")
        self.sync = SyncService(
            self.store,
            export_queue=self.tmp / "export",
            update_inbox=self.tmp / "inbox",
            pack_active=self.tmp / "active_pack.json",
            key_path=self.key_path,
        )

    def test_pull_valid_pack(self):
        pack = sign_pack(sample_pack(), self.key)
        inbox = self.tmp / "inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        (inbox / "new_pack.json").write_text(json.dumps(pack), encoding="utf-8")
        ok, msg = self.sync.pull_pack_updates()
        self.assertTrue(ok, msg)
        self.assertTrue(self.sync.pack_active.is_file())

    def test_pull_rejects_bad_sig(self):
        pack = sample_pack()
        pack["signature"] = {"alg": "hmac-sha256-dev", "value": "unsigned"}
        inbox = self.tmp / "inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        (inbox / "bad.json").write_text(json.dumps(pack), encoding="utf-8")
        ok, msg = self.sync.pull_pack_updates()
        self.assertFalse(ok)

    def test_enqueue_evidence(self):
        pack = sign_pack(sample_pack(), self.key)
        event = {
            "schema_version": "1.0.0",
            "id": "evt-2",
            "ts": "2026-10-20T12:00:00Z",
            "type": "health",
            "subject": {"device": "d"},
        }
        result = process_event(event, pack)
        self.store.write(result.evidence)
        path = self.sync.enqueue_evidence(result.evidence["id"])
        self.assertIsNotNone(path)
        self.assertIn(result.evidence["id"], self.sync.drain_export_queue())


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    sys.exit(0 if ok else 1)
