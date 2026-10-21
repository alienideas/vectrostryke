#!/usr/bin/env python3
"""Phase 0 contract tests — run: python3 tests/test_contracts.py"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from validate import (  # noqa: E402
    ContractError,
    load_json,
    validate_action,
    validate_event,
    validate_evidence,
    validate_policy_pack,
)

FIX = ROOT / "fixtures"


class TestValidFixtures(unittest.TestCase):
    def test_event_valid(self):
        validate_event(load_json(FIX / "event.valid.json"))

    def test_action_valid(self):
        validate_action(load_json(FIX / "action.valid.json"))

    def test_policy_pack_valid(self):
        validate_policy_pack(load_json(FIX / "policy_pack.valid.json"))

    def test_evidence_valid(self):
        validate_evidence(load_json(FIX / "evidence.valid.json"))


class TestInvalidRejected(unittest.TestCase):
    def test_event_bad_type(self):
        with self.assertRaises(ContractError):
            validate_event(load_json(FIX / "event.invalid.json"))

    def test_policy_unsigned_rejected(self):
        with self.assertRaises(ContractError):
            validate_policy_pack(load_json(FIX / "policy_pack.unsigned.json"))

    def test_missing_schema_version(self):
        with self.assertRaises(ContractError):
            validate_event({"id": "x", "ts": "t", "type": "process", "subject": {}})

    def test_wrong_schema_version(self):
        with self.assertRaises(ContractError):
            validate_event({
                "schema_version": "9.9.9",
                "id": "x", "ts": "t", "type": "process", "subject": {},
            })

    def test_action_bad_kind(self):
        with self.assertRaises(ContractError):
            validate_action({
                "schema_version": "1.0.0",
                "id": "a", "ts": "t", "kind": "delete_everything", "result": "success",
            })

    def test_evidence_score_out_of_range(self):
        with self.assertRaises(ContractError):
            validate_evidence({
                "schema_version": "1.0.0",
                "id": "e", "ts": "t", "vectors": [], "score": 150,
                "impact_class": False, "decision": "observe", "actions": [],
                "integrity": {"hash_alg": "sha256", "hash": "x"},
            })


class TestLastKnownGoodSemantics(unittest.TestCase):
    """Documented Phase 0 behaviour: bad pack must not replace LKG (logic test)."""

    def test_reject_does_not_return_pack(self):
        good = load_json(FIX / "policy_pack.valid.json")
        bad = load_json(FIX / "policy_pack.unsigned.json")
        lkg = validate_policy_pack(good)
        with self.assertRaises(ContractError):
            validate_policy_pack(bad)
        self.assertEqual(lkg["id"], "pack-default")


if __name__ == "__main__":
    ok = unittest.main(verbosity=2, exit=False).result.wasSuccessful()
    sys.exit(0 if ok else 1)
