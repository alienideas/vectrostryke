"""
Phase 9 — optional Control Plane: inventory, policy push, event intake, approval routing.
Agents remain able to protect offline; this plane optimises multi-device / multi-tenant ops.
"""
from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ROOT.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(PLATFORM / "phase4" / "src"))
sys.path.insert(0, str(PLATFORM / "shared" / "contracts" / "src"))

from tenants import TenantStore  # noqa: E402
from pack_signing import load_key, verify_pack, sign_pack  # noqa: E402
from validate import validate_policy_pack  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ControlPlane:
    def __init__(self, data_root: Path, key_path: Path):
        self.tenants = TenantStore(data_root / "tenants")
        self.key_path = key_path
        self.data_root = data_root
        data_root.mkdir(parents=True, exist_ok=True)

    def register_device(self, tenant_id: str, device: dict) -> dict:
        self.tenants.assert_tenant(tenant_id)
        did = device.get("device_id") or f"dev-{uuid.uuid4().hex[:10]}"
        rec = {
            "device_id": did,
            "tenant_id": tenant_id,
            "hostname": device.get("hostname", "unknown"),
            "os": device.get("os", "linux"),
            "modules": device.get("modules") or ["AR"],
            "registered_ts": _now(),
            "last_seen_ts": _now(),
            "status": "registered",
        }
        path = self.tenants.isolate_path(tenant_id, "devices", f"{did}.json")
        path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        return rec

    def list_devices(self, tenant_id: str) -> List[dict]:
        self.tenants.assert_tenant(tenant_id)
        d = self.tenants.tenant_dir(tenant_id) / "devices"
        return [json.loads(p.read_text(encoding="utf-8")) for p in d.glob("*.json")]

    def heartbeat(self, tenant_id: str, device_id: str) -> dict:
        path = self.tenants.isolate_path(tenant_id, "devices", f"{device_id}.json")
        if not path.is_file():
            raise FileNotFoundError(device_id)
        rec = json.loads(path.read_text(encoding="utf-8"))
        if rec.get("tenant_id") != tenant_id:
            raise PermissionError("device tenant mismatch")
        rec["last_seen_ts"] = _now()
        path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        return rec

    def publish_pack(self, tenant_id: str, pack: dict) -> dict:
        self.tenants.assert_tenant(tenant_id)
        key = load_key(self.key_path)
        ok, msg = verify_pack(pack, key)
        if not ok:
            raise ValueError(f"pack rejected: {msg}")
        pack = validate_policy_pack(pack)
        dest = self.tenants.isolate_path(tenant_id, "packs", "active.json")
        dest.write_text(json.dumps(pack, indent=2), encoding="utf-8")
        ver = pack.get("version", "0")
        ver_path = self.tenants.isolate_path(tenant_id, "packs", f"pack-{ver}.json")
        ver_path.write_text(json.dumps(pack, indent=2), encoding="utf-8")
        return {"tenant_id": tenant_id, "pack_id": pack.get("id"), "version": ver, "path": str(dest)}

    def get_active_pack(self, tenant_id: str) -> Optional[dict]:
        path = self.tenants.isolate_path(tenant_id, "packs", "active.json")
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def pull_pack_for_device(self, tenant_id: str, device_id: str) -> Optional[dict]:
        devices = {d["device_id"]: d for d in self.list_devices(tenant_id)}
        if device_id not in devices:
            raise PermissionError("device not in tenant")
        return self.get_active_pack(tenant_id)

    def ingest_event(self, tenant_id: str, event: dict) -> Path:
        self.tenants.assert_tenant(tenant_id)
        eid = event.get("id") or f"evt-{uuid.uuid4().hex[:10]}"
        event = dict(event)
        event["id"] = eid
        event["tenant_id"] = tenant_id
        path = self.tenants.isolate_path(tenant_id, "events", f"{eid}.json")
        path.write_text(json.dumps(event, indent=2), encoding="utf-8")
        return path

    def list_events(self, tenant_id: str, limit: int = 50) -> List[dict]:
        d = self.tenants.tenant_dir(tenant_id) / "events"
        files = sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        return [json.loads(p.read_text(encoding="utf-8")) for p in files[:limit]]

    def stage_approval(self, tenant_id: str, pending: dict) -> dict:
        self.tenants.assert_tenant(tenant_id)
        pid = pending.get("pending_id") or f"pending-{uuid.uuid4().hex[:10]}"
        rec = dict(pending)
        rec["pending_id"] = pid
        rec["tenant_id"] = tenant_id
        rec["status"] = "pending"
        rec["created_ts"] = _now()
        path = self.tenants.isolate_path(tenant_id, "approvals", f"{pid}.json")
        path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        return rec

    def list_approvals(self, tenant_id: str) -> List[dict]:
        d = self.tenants.tenant_dir(tenant_id) / "approvals"
        rows = []
        for p in d.glob("*.json"):
            rec = json.loads(p.read_text(encoding="utf-8"))
            if rec.get("status") == "pending":
                rows.append(rec)
        return rows

    def resolve_approval(self, tenant_id: str, pending_id: str, approved: bool) -> dict:
        path = self.tenants.isolate_path(tenant_id, "approvals", f"{pending_id}.json")
        if not path.is_file():
            raise FileNotFoundError(pending_id)
        rec = json.loads(path.read_text(encoding="utf-8"))
        if rec.get("tenant_id") != tenant_id:
            raise PermissionError("cross-tenant approval denied")
        rec["status"] = "approved" if approved else "denied"
        rec["resolved_ts"] = _now()
        path.write_text(json.dumps(rec, indent=2), encoding="utf-8")
        return rec

    def tenant_cannot_read_other(self, tenant_a: str, tenant_b: str) -> bool:
        try:
            self.tenants.isolate_path(tenant_a, "packs", "active.json")
        except KeyError:
            return True
        a_devices = self.list_devices(tenant_a)
        for d in a_devices:
            if d.get("tenant_id") == tenant_b:
                return False
        b_events = {e.get("id") for e in self.list_events(tenant_b)}
        a_events = {e.get("id") for e in self.list_events(tenant_a)}
        return b_events.isdisjoint(a_events) or not b_events
