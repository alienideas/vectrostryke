"""Data contracts – VSFileInfo, VSRunContext, VSStageResult."""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class VSFileInfo:
    full_name: str
    length: int = 0
    creation_time_utc: Optional[datetime] = None
    last_write_time_utc: Optional[datetime] = None
    owner: str = "unknown"
    is_signed: bool = False
    signature_status: str = "NotSigned"
    hash_sha256: Optional[str] = None
    entropy: float = 0.0
    ml_score: float = 0.0
    remote_reputation: Optional[float] = None
    score: float = 0.0
    classification: str = "Clean"
    action_taken: str = "None"

    @classmethod
    def from_path(cls, path: str | Path) -> "VSFileInfo":
        p = Path(path)
        st = p.stat()
        try:
            owner = p.owner()
        except Exception:
            owner = "unknown"
        return cls(
            full_name=str(p.resolve()),
            length=st.st_size,
            creation_time_utc=datetime.fromtimestamp(st.st_ctime, tz=timezone.utc),
            last_write_time_utc=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
            owner=owner,
        )

    def to_report_item(self) -> Dict[str, Any]:
        return {
            "FilePath": self.full_name,
            "Score": self.score,
            "Classification": self.classification,
            "ActionTaken": self.action_taken,
            "TimestampUtc": datetime.now(timezone.utc).isoformat(),
            "HashSha256": self.hash_sha256,
            "Entropy": self.entropy,
            "MLScore": self.ml_score,
            "IsSigned": self.is_signed,
        }


@dataclass
class VSStageResult:
    stage_name: str
    status: str = "Success"
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class VSConfig:
    exclusions: List[str] = field(default_factory=lambda: [
        "/proc", "/sys", "/dev", "/run", "/tmp",
        "/var/cache", "/var/tmp", "/lost+found",
    ])
    safe_zones: List[str] = field(default_factory=lambda: [
        str(Path.home()), "/opt", "/usr/local", "/var/www",
    ])
    quarantine_path: str = field(default_factory=lambda: str(
        Path.home() / ".local/share/vectorstryke-av/quarantine"
    ))
    report_path: str = field(default_factory=lambda: str(
        Path.home() / ".local/share/vectorstryke-av/reports"
    ))
    default_threads: int = 2
    quarantine_threshold: float = 0.20
    malicious_threshold: float = 0.60
    max_file_bytes: int = 32 * 1024 * 1024

    def is_excluded(self, full_path: str) -> bool:
        norm = full_path.lower()
        for ex in self.exclusions:
            if norm.startswith(ex.lower()) or f"/{ex.strip('/').lower()}/" in norm:
                return True
        return False


@dataclass
class VSOptions:
    mode: str = "QuickScan"
    threads: int = 2
    quiet: bool = False


@dataclass
class VSCounters:
    files_scanned: int = 0
    files_quarantined: int = 0
    files_deleted: int = 0
    files_skipped: int = 0
    errors: int = 0


@dataclass
class VSCache:
    remote: Dict[str, float] = field(default_factory=dict)
    hash_index: Dict[str, str] = field(default_factory=dict)


@dataclass
class VSRunContext:
    config: VSConfig
    options: VSOptions
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    start_time_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cache: VSCache = field(default_factory=VSCache)
    counters: VSCounters = field(default_factory=VSCounters)
    pipeline: List[Any] = field(default_factory=list)
    file_collection: List[VSFileInfo] = field(default_factory=list)
    temp_path: str = ""

    def __post_init__(self) -> None:
        if not self.temp_path:
            self.temp_path = f"/tmp/vectorstryke-av-{self.run_id}"
        os.makedirs(self.temp_path, exist_ok=True)
        os.makedirs(self.config.quarantine_path, exist_ok=True)
        os.makedirs(self.config.report_path, exist_ok=True)

    def cleanup(self) -> None:
        import shutil
        if self.temp_path and os.path.isdir(self.temp_path):
            shutil.rmtree(self.temp_path, ignore_errors=True)
