"""Data contracts – VSFileInfo, VSRunContext."""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

@dataclass
class VSFileInfo:
    full_name: str
    length: int = 0
    is_signed: bool = False
    signature_status: str = "NotSigned"
    hash_sha256: Optional[str] = None
    entropy: float = 0.0
    ml_score: float = 0.0
    remote_reputation: Optional[float] = None
    score: float = 0.0
    classification: str = "Clean"
    action_taken: str = "None"

@dataclass
class VSConfig:
    exclusions: List[str] = field(default_factory=lambda: ["/proc", "/sys", "/dev", "/run", "/tmp"])
    quarantine_path: str = field(default_factory=lambda: str(Path.home() / ".local/share/vectorstryke-av/quarantine"))
    report_path: str = field(default_factory=lambda: str(Path.home() / ".local/share/vectorstryke-av/reports"))
    quarantine_threshold: float = 0.20
    malicious_threshold: float = 0.60
    default_threads: int = 2

    def is_excluded(self, full_path: str) -> bool:
        norm = full_path.lower()
        return any(norm.startswith(ex.lower()) for ex in self.exclusions)

@dataclass
class VSOptions:
    mode: str = "QuickScan"
    threads: int = 2
    quiet: bool = False

@dataclass
class VSCounters:
    files_scanned: int = 0
    files_quarantined: int = 0
    errors: int = 0

@dataclass
class VSRunContext:
    config: VSConfig
    options: VSOptions
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    counters: VSCounters = field(default_factory=VSCounters)
    file_collection: List[VSFileInfo] = field(default_factory=list)
    pipeline: List[Any] = field(default_factory=list)
