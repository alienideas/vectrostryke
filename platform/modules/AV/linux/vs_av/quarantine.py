"""Quarantine store."""
from __future__ import annotations
from pathlib import Path
from .models import VSFileInfo, VSRunContext

class VSQuarantine:
    def __init__(self, ctx: VSRunContext):
        self.ctx = ctx
        Path(ctx.config.quarantine_path).mkdir(parents=True, exist_ok=True)
    def add(self, fi: VSFileInfo) -> None:
        fi.action_taken = "Quarantined"
        self.ctx.counters.files_quarantined += 1
