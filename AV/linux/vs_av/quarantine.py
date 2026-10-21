"""Quarantine with openssl AES when available; copy fallback otherwise."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .models import VSFileInfo, VSRunContext


class VSQuarantine:
    def __init__(self, ctx: VSRunContext) -> None:
        self.ctx = ctx
        self.container = Path(ctx.config.quarantine_path)
        self.container.mkdir(parents=True, exist_ok=True)
        self.manifest = self.container / "manifest.jsonl"

    def _derive_key_hex(self) -> str:
        machine = ""
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if os.path.isfile(p):
                machine = Path(p).read_text().strip()
                break
        material = f"{os.environ.get('USER', 'user')}-{machine}-{self.ctx.run_id}"
        return hashlib.pbkdf2_hmac("sha256", material.encode(), b"VectorStrykeAV", 100_000).hex()

    def add(self, fi: VSFileInfo) -> None:
        guid = uuid.uuid4().hex
        dest = self.container / f"{guid}.qz"
        try:
            key = self._derive_key_hex()[:64]
            iv = os.urandom(16).hex()
            openssl = shutil.which("openssl")
            if openssl:
                cmd = [
                    openssl, "enc", "-aes-256-cbc", "-salt",
                    "-in", fi.full_name, "-out", str(dest),
                    "-K", key, "-iv", iv,
                ]
                subprocess.run(cmd, check=True, capture_output=True)
            else:
                shutil.copy2(fi.full_name, dest)
                dest.with_suffix(".keymeta").write_text(json.dumps({"iv": iv, "note": "copy-fallback"}))

            entry = {
                "Id": guid,
                "OriginalPath": fi.full_name,
                "Sha256": fi.hash_sha256,
                "Score": fi.score,
                "Classification": fi.classification,
                "TimestampUtc": datetime.now(timezone.utc).isoformat(),
                "QuarantineFile": str(dest),
            }
            with open(self.manifest, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            fi.action_taken = "Quarantined"
            self.ctx.counters.files_quarantined += 1
        except Exception as exc:
            self.ctx.counters.errors += 1
            fi.action_taken = f"QuarantineFailed: {exc}"

    def review_and_apply(self, candidates: List[VSFileInfo]) -> None:
        if not candidates:
            return
        for fi in candidates:
            if fi.classification in ("Quarantine", "Malicious"):
                if self._is_protected(fi.full_name):
                    fi.action_taken = "SkippedProtected"
                    continue
                self.add(fi)
        self._write_review_html(candidates)

    def _is_protected(self, path: str) -> bool:
        protected = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/", "/etc/")
        return any(path.startswith(p) for p in protected)

    def _write_review_html(self, items: List[VSFileInfo]) -> None:
        rows = []
        for fi in items:
            rows.append(
                f"<tr><td>{fi.full_name}</td><td>{fi.score}</td>"
                f"<td>{fi.classification}</td><td><code>{fi.hash_sha256 or ''}</code></td>"
                f"<td>{fi.action_taken}</td></tr>"
            )
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VectorStryke AV – Quarantine Review</title></head>
<body><h1>Quarantine Review</h1><p>Run {self.ctx.run_id}</p>
<table><tr><th>Path</th><th>Score</th><th>Class</th><th>SHA-256</th><th>Action</th></tr>
{''.join(rows)}</table></body></html>"""
        out = Path(self.ctx.config.report_path) / f"QuarantineReview_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        out.write_text(html, encoding="utf-8")
