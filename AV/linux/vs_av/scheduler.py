"""Discovery + parallel workers (ThreadPoolExecutor)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

from .models import VSFileInfo, VSRunContext
from .pipeline import VSPipelineStage


class VSScheduler:
    def __init__(self, ctx: VSRunContext) -> None:
        self.ctx = ctx

    def enqueue_files(self) -> List[VSFileInfo]:
        roots = self.ctx.config.safe_zones
        if self.ctx.options.mode == "QuickScan":
            home = str(Path.home())
            roots = [home, str(Path.home() / "Downloads"), str(Path.home() / "Desktop")]

        files: List[VSFileInfo] = []
        for root in roots:
            p = Path(root)
            if not p.exists():
                continue
            try:
                for f in p.rglob("*"):
                    if not f.is_file():
                        continue
                    full = str(f.resolve())
                    if self.ctx.config.is_excluded(full):
                        self.ctx.counters.files_skipped += 1
                        continue
                    try:
                        size = f.stat().st_size
                    except OSError:
                        continue
                    if size <= 0 or size > 100 * 1024 * 1024:
                        self.ctx.counters.files_skipped += 1
                        continue
                    try:
                        files.append(VSFileInfo.from_path(full))
                    except Exception:
                        self.ctx.counters.errors += 1
            except PermissionError:
                self.ctx.counters.errors += 1
        return files

    def run_pipeline(self, files: List[VSFileInfo], stages: List[VSPipelineStage]) -> None:
        def _one(fi: VSFileInfo) -> VSFileInfo:
            for stage in stages:
                stage.process(fi)
            return fi

        workers = max(1, self.ctx.options.threads)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_one, fi) for fi in files]
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                    self.ctx.file_collection.append(result)
                    self.ctx.counters.files_scanned += 1
                except Exception:
                    self.ctx.counters.errors += 1
