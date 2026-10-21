"""Phase 9 — multi-tenant isolation model (MSSP-ready)."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TenantStore:
    """File-backed tenant registry with strict data separation by tenant_id."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = root / "tenants_index.json"
        self._index: Dict[str, dict] = {}
        if self.index_path.is_file():
            self._index = json.loads(self.index_path.read_text(encoding="utf-8"))

    def _save_index(self) -> None:
        self.index_path.write_text(json.dumps(self._index, indent=2), encoding="utf-8")

    def tenant_dir(self, tenant_id: str) -> Path:
        d = self.root / tenant_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "devices").mkdir(exist_ok=True)
        (d / "events").mkdir(exist_ok=True)
        (d / "packs").mkdir(exist_ok=True)
        (d / "approvals").mkdir(exist_ok=True)
        return d

    def create_tenant(self, name: str, *, mssp: bool = False, parent_id: Optional[str] = None) -> dict:
        tid = f"tnt-{uuid.uuid4().hex[:10]}"
        rec = {
            "tenant_id": tid,
            "name": name,
            "mssp": mssp,
            "parent_id": parent_id,
            "created_ts": _now(),
            "status": "active",
        }
        self._index[tid] = rec
        self._save_index()
        self.tenant_dir(tid)
        return rec

    def get(self, tenant_id: str) -> Optional[dict]:
        return self._index.get(tenant_id)

    def list_tenants(self) -> List[dict]:
        return list(self._index.values())

    def assert_tenant(self, tenant_id: str) -> dict:
        t = self.get(tenant_id)
        if not t or t.get("status") != "active":
            raise KeyError(f"unknown or inactive tenant: {tenant_id}")
        return t

    def isolate_path(self, tenant_id: str, *parts: str) -> Path:
        self.assert_tenant(tenant_id)
        base = self.tenant_dir(tenant_id).resolve()
        path = base.joinpath(*parts).resolve()
        if not str(path).startswith(str(base)):
            raise PermissionError("path escapes tenant boundary")
        return path
