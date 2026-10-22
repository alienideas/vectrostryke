"""File enumeration."""
from __future__ import annotations
from .models import VSRunContext

class VSScheduler:
    def __init__(self, ctx: VSRunContext):
        self.ctx = ctx
    def enqueue_files(self) -> None:
        pass
