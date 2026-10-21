#!/usr/bin/env python3
"""Run full Phase 11 CI gate suite; exit 1 if any fail."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ci_gates import run_all_gates  # noqa: E402


def main() -> int:
    results = run_all_gates(include_optional=True)
    report = Path(__file__).resolve().parents[1] / "reports" / "gate_report.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(results, indent=2), encoding="utf-8")
    failed = [r for r in results if not r["passed"]]
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"{status}  {r['test']}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    print(f"Report: {report}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
