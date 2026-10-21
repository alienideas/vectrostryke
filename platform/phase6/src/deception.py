"""Phase 6 — deception canaries: files, credentials, hosts; tripwire Events."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "1.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


def make_deception_event(
    *,
    canary_type: str,
    name: str,
    op: str,
    user: Optional[str] = None,
    device: Optional[str] = None,
    extra: Optional[dict] = None,
) -> dict:
    attrs = {
        "canary_type": canary_type,
        "canary_name": name,
        "deception_tripwire": True,
        "op": op,
    }
    if extra:
        attrs.update(extra)
    return {
        "schema_version": SCHEMA,
        "id": _id(),
        "ts": _now(),
        "type": "deception",
        "subject": {
            "device": device or os.uname().nodename,
            "user": user or os.environ.get("USER", "unknown"),
        },
        "object": {"canary": name, "canary_type": canary_type, "op": op},
        "attrs": attrs,
        "geo_ip": None,
        "last_logon_age_sec": None,
        "mitm_indicators": [],
        "technique_ids": ["T1555"] if canary_type == "credential" else [],
    }


class CanaryRegistry:
    """Deploy and watch canary files on disk (safe local markers)."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.manifest_path = root / "canary_manifest.json"
        self._manifest: Dict[str, Any] = {"files": {}, "credentials": [], "hosts": []}
        if self.manifest_path.is_file():
            self._manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        self.manifest_path.write_text(json.dumps(self._manifest, indent=2), encoding="utf-8")

    def deploy_file_canary(self, name: str, content: Optional[str] = None) -> Path:
        path = self.root / name
        body = content or f"VS_CANARY_DO_NOT_TOUCH id={uuid.uuid4().hex}\n"
        path.write_text(body, encoding="utf-8")
        self._manifest["files"][name] = {
            "path": str(path),
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "deployed_ts": _now(),
        }
        self._save()
        return path

    def deploy_credential_canary(self, username: str, secret_hint: str = "canary-secret") -> dict:
        rec = {"username": username, "secret_hint": secret_hint, "deployed_ts": _now()}
        self._manifest.setdefault("credentials", []).append(rec)
        self._save()
        return rec

    def deploy_host_canary(self, hostname: str, ip: str = "203.0.113.50") -> dict:
        rec = {"hostname": hostname, "ip": ip, "deployed_ts": _now()}
        self._manifest.setdefault("hosts", []).append(rec)
        self._save()
        return rec

    def check_file_tripwires(self) -> List[dict]:
        events = []
        for name, meta in list(self._manifest.get("files", {}).items()):
            path = Path(meta["path"])
            if not path.is_file():
                events.append(make_deception_event(
                    canary_type="file", name=name, op="missing",
                    extra={"detail": "file_removed"},
                ))
                continue
            body = path.read_text(encoding="utf-8")
            digest = hashlib.sha256(body.encode()).hexdigest()
            if digest != meta.get("sha256"):
                events.append(make_deception_event(
                    canary_type="file", name=name, op="write",
                    extra={"detail": "content_changed"},
                ))
        return events

    def trip_credential(self, username: str, op: str = "auth_attempt") -> dict:
        return make_deception_event(canary_type="credential", name=username, op=op)

    def trip_host(self, hostname: str, op: str = "connect") -> dict:
        return make_deception_event(canary_type="host", name=hostname, op=op)
