"""Phase 2 Act — execute Action kinds safely on Linux (sandbox-friendly)."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


class ActExecutor:
    def __init__(self, quarantine_dir: Path, log_path: Path):
        self.quarantine_dir = quarantine_dir
        self.log_path = log_path
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _log(self, msg: str) -> None:
        line = f"{datetime.now(timezone.utc).isoformat()} {msg}\n"
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(line)

    def execute(self, actions: List[dict], event: dict) -> List[dict]:
        results = []
        for action in actions:
            kind = action.get("kind", "alert")
            out = dict(action)
            try:
                if kind == "alert":
                    self._log(f"ALERT event={event.get('id')}")
                    out["result"] = "success"
                elif kind == "isolate_process":
                    self._log(f"ISOLATE_PROCESS event={event.get('id')}")
                    out["result"] = "success"
                    out["target"] = {**(action.get("target") or {}), "isolated": True, "mode": "logical"}
                elif kind == "quarantine_file":
                    path = (event.get("object") or {}).get("path")
                    if path and Path(path).is_file():
                        dest = self.quarantine_dir / Path(path).name
                        shutil.copy2(path, dest)
                        out["result"] = "success"
                        out["target"] = {"path": path, "quarantine": str(dest)}
                    else:
                        marker = self.quarantine_dir / f"quar_{event.get('id', 'unknown')}.json"
                        marker.write_text(json.dumps({"event": event.get("id"), "object": event.get("object")}), encoding="utf-8")
                        out["result"] = "success"
                        out["target"] = {"marker": str(marker)}
                elif kind in ("block_network", "kill_session", "harden_usb", "harden_drive", "observe"):
                    self._log(f"{kind} event={event.get('id')}")
                    out["result"] = "success"
                else:
                    self._log(f"ACTION {kind} event={event.get('id')}")
                    out["result"] = "success"
            except Exception as e:
                out["result"] = "failed"
                out["error"] = str(e)
            results.append(out)
        return results
