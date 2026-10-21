"""VSOrchestrator – composition root for Linux AV scan."""
from __future__ import annotations

from .models import VSRunContext
from .pipeline import STAGE_CLASSES
from .quarantine import VSQuarantine
from .reporter import VSReporter
from .scheduler import VSScheduler
from .scorer import VSScorer


class VSOrchestrator:
    def __init__(self, ctx: VSRunContext) -> None:
        self.ctx = ctx

    def run(self) -> None:
        if not self.ctx.options.quiet:
            print(f"[VectorStryke AV] RunId={self.ctx.run_id} Mode={self.ctx.options.mode} Threads={self.ctx.options.threads}")

        if self.ctx.options.mode == "UpdateIndex":
            if not self.ctx.options.quiet:
                print("UpdateIndex: not fully implemented on Linux (hash index placeholder).")
            return

        stages = [cls(self.ctx) for cls in STAGE_CLASSES]
        stages.sort(key=lambda s: s.priority)
        self.ctx.pipeline = stages
        if not self.ctx.options.quiet:
            print("Pipeline:", " → ".join(s.name for s in stages))

        scheduler = VSScheduler(self.ctx)
        files = scheduler.enqueue_files()
        if not self.ctx.options.quiet:
            print(f"Queued {len(files)} files")

        scheduler.run_pipeline(files, stages)

        for fi in self.ctx.file_collection:
            fi.score = VSScorer.compute_score(fi)
            fi.classification = VSScorer.classify(
                fi.score,
                self.ctx.config.quarantine_threshold,
                self.ctx.config.malicious_threshold,
            )

        candidates = [fi for fi in self.ctx.file_collection if fi.classification in ("Quarantine", "Malicious")]
        q = VSQuarantine(self.ctx)
        q.review_and_apply(candidates)

        reporter = VSReporter(self.ctx)
        reporter.export_all()

        self.ctx.cleanup()
        if not self.ctx.options.quiet:
            c = self.ctx.counters
            print(f"Done. Scanned={c.files_scanned} Quarantined={c.files_quarantined} Errors={c.errors}")
