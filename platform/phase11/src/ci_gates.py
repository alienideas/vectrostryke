"""Phase 11 — aggregate CI gate runner for platform phase tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

PLATFORM = Path(__file__).resolve().parents[2]

GATE_TESTS = [
    PLATFORM / "shared/contracts/tests/test_contracts.py",
    PLATFORM / "decision_core/tests/test_decision_core.py",
    PLATFORM / "phase4/tests/test_phase4.py",
    PLATFORM / "phase5/tests/test_phase5.py",
    PLATFORM / "phase6/tests/test_phase6.py",
    PLATFORM / "phase7/tests/test_phase7.py",
    PLATFORM / "phase8/tests/test_phase8.py",
    PLATFORM / "phase9/tests/test_phase9.py",
    PLATFORM / "phase10/tests/test_phase10.py",
    PLATFORM / "phase11/tests/test_phase11.py",
]

OPTIONAL = [
    PLATFORM.parent / "AR/Linux/phase2/tests/test_phase2_e2e.py",
    PLATFORM.parent / "AR/Linux/phase3/tests/test_phase3_operator.py",
]


def run_gate(path: Path) -> Tuple[str, bool, str]:
    if not path.is_file():
        return str(path), False, "missing"
    proc = subprocess.run(
        [sys.executable, str(path)],
        capture_output=True,
        text=True,
        cwd=str(PLATFORM.parent),
    )
    ok = proc.returncode == 0
    tail = (proc.stdout or "")[-500:] + (proc.stderr or "")[-300:]
    return str(path.relative_to(PLATFORM.parent)), ok, tail


def run_all_gates(include_optional: bool = True) -> List[dict]:
    paths = list(GATE_TESTS)
    if include_optional:
        paths.extend(OPTIONAL)
    results = []
    for p in paths:
        name, ok, detail = run_gate(p)
        results.append({"test": name, "passed": ok, "detail": detail if not ok else "OK"})
    return results
