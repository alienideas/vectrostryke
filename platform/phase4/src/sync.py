"""Phase 4 — basic sync: export evidence queue + pull pack updates from inbox dir."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from pack_signing import load_key, verify_pack
from evidence_store import EvidenceStore


class SyncService:
    def __init__(
        self,
        evidence_store: EvidenceStore,
        export_queue: Path,
        update_inbox: Path,
        pack_active: Path,
        key_path: Path,
    ):
        self.store = evidence_store
        self.export_queue = export_queue
        self.update_inbox = update_inbox
        self.pack_active = pack_active
        self.key_path = key_path
        self.export_queue.mkdir(parents=True, exist_ok=True)
        self.update_inbox.mkdir(parents=True, exist_ok=True)

    def enqueue_evidence(self, evidence_id: str) -> Optional[Path]:
        ev = self.store.read(evidence_id)
        if not ev:
            return None
        ok, _ = self.store.verify(ev)
        if not ok:
            return None
        dest = self.export_queue / f"{evidence_id}.json"
        dest.write_text(json.dumps(ev, indent=2), encoding="utf-8")
        return dest

    def drain_export_queue(self) -> List[str]:
        return sorted(p.stem for p in self.export_queue.glob("*.json"))

    def pull_pack_updates(self) -> tuple[bool, str]:
        key = load_key(self.key_path)
        candidates = sorted(self.update_inbox.glob("*.json"))
        if not candidates:
            return False, "no updates"
        for path in candidates:
            try:
                pack = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            ok, msg = verify_pack(pack, key)
            if not ok:
                return False, f"rejected {path.name}: {msg}"
            self.pack_active.parent.mkdir(parents=True, exist_ok=True)
            self.pack_active.write_text(json.dumps(pack, indent=2), encoding="utf-8")
            done = self.update_inbox / f"applied_{path.name}"
            path.rename(done)
            return True, f"applied {path.name}"
        return False, "no valid packs"
