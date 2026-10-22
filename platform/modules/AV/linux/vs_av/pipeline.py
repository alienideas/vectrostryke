"""Pipeline stage base."""
from __future__ import annotations
from .models import VSFileInfo, VSRunContext

class VSPipelineStage:
    name = "Base"
    def __init__(self, ctx: VSRunContext):
        self.ctx = ctx
    def process(self, fi: VSFileInfo) -> VSFileInfo:
        return fi
