"""Phase 4 — durable Evidence store with integrity verify and simple retention."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class EvidenceStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, evidence_id: str) -> Path:
        return self.root / f"{evidence_id}.json"

    def write(self, evidence: dict) -> Path:
        eid = evidence.get("id")
        if not eid:
            raise ValueError("evidence.id required")
        if "integrity" not in evidence or not evidence["integrity"].get("hash"):
            evidence = dict(evidence)
            evidence["integrity"] = self.compute_integrity(evidence)
        path = self._path(eid)
        path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        return path

    @staticmethod
    def compute_integrity(evidence: dict) -> dict:
        body = {
            k: evidence.get(k)
            for k in ("id", "ts", "vectors", "score", "impact_class", "decision", "actions")
        }
        canon = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {"hash_alg": "sha256", "hash": hashlib.sha256(canon).hexdigest()}

    def read(self, evidence_id: str) -> Optional[dict]:
        path = self._path(evidence_id)
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def verify(self, evidence: dict) -> tuple[bool, str]:
        integ = evidence.get("integrity") or {}
        if not integ.get("hash"):
            return False, "missing integrity.hash"
        expected = self.compute_integrity(evidence)["hash"]
        if integ.get("hash") != expected:
            return False, "integrity mismatch"
        return True, "ok"

    def list_ids(self) -> List[str]:
        return sorted(p.stem for p in self.root.glob("*.json"))

    def retain_last_n(self, n: int) -> int:
        files = sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        deleted = 0
        for p in files[n:]:
            p.unlink(missing_ok=True)
            deleted += 1
        return deleted
