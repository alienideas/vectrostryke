"""File-backed pending approvals and evidence index (offline operator surface)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


class OperatorStore:
    def __init__(self, root: Path):
        self.root = root
        self.pending_dir = root / "pending"
        self.evidence_dir = root / "evidence"
        self.audit_log = root / "operator_audit.log"
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def save_pending(self, record: dict) -> Path:
        pid = record["pending_id"]
        path = self.pending_dir / f"{pid}.json"
        record = dict(record)
        record["status"] = "pending"
        record.setdefault("created_ts", self._now())
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        self._audit(f"STAGE {pid}")
        return path

    def list_pending(self) -> List[dict]:
        rows = []
        for p in sorted(self.pending_dir.glob("*.json")):
            try:
                rows.append(json.loads(p.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
        return [r for r in rows if r.get("status") == "pending"]

    def get_pending(self, pending_id: str) -> Optional[dict]:
        path = self.pending_dir / f"{pending_id}.json"
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def mark_resolved(self, pending_id: str, status: str, extra: dict | None = None) -> None:
        path = self.pending_dir / f"{pending_id}.json"
        if not path.is_file():
            raise FileNotFoundError(pending_id)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["status"] = status
        data["resolved_ts"] = self._now()
        if extra:
            data.update(extra)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._audit(f"{status.upper()} {pending_id}")

    def list_evidence(self, limit: int = 50) -> List[dict]:
        files = sorted(self.evidence_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        out = []
        for p in files[:limit]:
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
        return out

    def get_evidence(self, evidence_id: str) -> Optional[dict]:
        path = self.evidence_dir / f"{evidence_id}.json"
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
        for p in self.evidence_dir.glob("*.json"):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                if d.get("id") == evidence_id:
                    return d
            except json.JSONDecodeError:
                continue
        return None

    def status_summary(self) -> dict:
        return {
            "ts": self._now(),
            "pending_count": len(self.list_pending()),
            "evidence_count": len(list(self.evidence_dir.glob("*.json"))),
            "offline": True,
            "control_plane": False,
        }

    def write_status_json(self, path: Path) -> None:
        payload = {
            "summary": self.status_summary(),
            "pending": self.list_pending(),
            "evidence_recent": self.list_evidence(10),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _audit(self, msg: str) -> None:
        with self.audit_log.open("a", encoding="utf-8") as f:
            f.write(f"{self._now()} {msg}\n")
