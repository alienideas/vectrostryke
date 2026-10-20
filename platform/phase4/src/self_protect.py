"""Phase 4 — agent self-protection: file integrity manifest + degraded mode."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Tuple


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(paths: List[Path], base: Path) -> dict:
    files = {}
    for p in paths:
        if p.is_file():
            try:
                rel = str(p.resolve().relative_to(base.resolve()))
            except ValueError:
                rel = p.name
            files[rel] = file_sha256(p)
    return {"files": files, "status": "healthy"}


def verify_manifest(manifest: dict, base: Path) -> Tuple[str, List[str]]:
    problems = []
    for rel, expected in (manifest.get("files") or {}).items():
        path = base / rel
        if not path.is_file():
            problems.append(f"missing:{rel}")
            continue
        actual = file_sha256(path)
        if actual != expected:
            problems.append(f"tampered:{rel}")
    status = "healthy" if not problems else "degraded"
    return status, problems


def save_manifest(path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
