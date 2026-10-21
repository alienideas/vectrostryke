"""JSON-L and HTML report generation."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .models import VSRunContext


class VSReporter:
    def __init__(self, ctx: VSRunContext) -> None:
        self.ctx = ctx

    def export_all(self) -> None:
        out_dir = Path(self.ctx.config.report_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        jsonl = out_dir / f"Report_{stamp}.jsonl"
        html_path = out_dir / f"Report_{stamp}.html"

        with open(jsonl, "w", encoding="utf-8") as f:
            for fi in self.ctx.file_collection:
                f.write(json.dumps(fi.to_report_item()) + "\n")

        rows = []
        for fi in sorted(self.ctx.file_collection, key=lambda x: x.score, reverse=True):
            cls = {"Malicious": "mal", "Quarantine": "qua"}.get(fi.classification, "clean")
            rows.append(
                f"<tr><td>{fi.full_name}</td><td>{fi.score}</td>"
                f"<td class='{cls}'>{fi.classification}</td>"
                f"<td>{fi.entropy}</td><td>{fi.ml_score}</td>"
                f"<td>{fi.is_signed}</td><td>{fi.action_taken}</td></tr>"
            )

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VectorStryke AV Report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:24px;background:#0f172a;color:#e2e8f0}}
h1{{color:#38bdf8}} table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #334155;padding:6px 8px;font-size:13px}}
th{{background:#1e293b}} .mal{{color:#f87171}} .qua{{color:#fbbf24}} .clean{{color:#4ade80}}
.card{{background:#1e293b;padding:12px;border-radius:8px;display:inline-block;margin:4px}}
</style></head><body>
<h1>VectorStryke AV Scan Report</h1>
<div class="card"><b>Run</b><br>{self.ctx.run_id}</div>
<div class="card"><b>Mode</b><br>{self.ctx.options.mode}</div>
<div class="card"><b>Scanned</b><br>{self.ctx.counters.files_scanned}</div>
<div class="card"><b>Quarantined</b><br>{self.ctx.counters.files_quarantined}</div>
<table>
<tr><th>File</th><th>Score</th><th>Class</th><th>Entropy</th><th>ML</th><th>Signed</th><th>Action</th></tr>
{''.join(rows)}
</table></body></html>"""
        html_path.write_text(html, encoding="utf-8")
        if not self.ctx.options.quiet:
            print(f"Reports: {jsonl} | {html_path}")
