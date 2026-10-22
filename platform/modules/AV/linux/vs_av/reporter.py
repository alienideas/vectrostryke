"""Reports."""
from __future__ import annotations
from .models import VSRunContext

class VSReporter:
    def __init__(self, ctx: VSRunContext):
        self.ctx = ctx
    def export_all(self) -> None:
        pass
