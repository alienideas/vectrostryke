"""Abstract pipeline stage + concrete analysis stages."""
from __future__ import annotations

import hashlib
import math
import os
from abc import ABC, abstractmethod
from collections import Counter
from pathlib import Path

from .models import VSFileInfo, VSRunContext, VSStageResult


class VSPipelineStage(ABC):
    name: str = "VSPipelineStage"
    priority: int = 100

    def __init__(self, ctx: VSRunContext) -> None:
        self.ctx = ctx
        self.name = self.__class__.__name__

    @abstractmethod
    def process(self, fi: VSFileInfo) -> None:
        ...

    def run(self, fi: VSFileInfo) -> VSStageResult:
        result = VSStageResult(stage_name=self.name)
        try:
            self.process(fi)
            result.status = "Success"
        except Exception as exc:
            result.status = "Error"
            result.data["Error"] = str(exc)
            self.ctx.counters.errors += 1
        return result


class HashStage(VSPipelineStage):
    priority = 10

    def process(self, fi: VSFileInfo) -> None:
        if fi.hash_sha256:
            return
        h = hashlib.sha256()
        with open(fi.full_name, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        fi.hash_sha256 = h.hexdigest()


class SignatureStage(VSPipelineStage):
    priority = 20

    def process(self, fi: VSFileInfo) -> None:
        path = Path(fi.full_name)
        if path.is_file() and str(path).startswith(("/usr/", "/bin/", "/sbin/")):
            fi.is_signed = True
            fi.signature_status = "SystemPath"
        else:
            fi.is_signed = False
            fi.signature_status = "NotSigned"


class EntropyStage(VSPipelineStage):
    priority = 30

    def process(self, fi: VSFileInfo) -> None:
        if fi.length == 0 or fi.length > self.ctx.config.max_file_bytes:
            fi.entropy = 0.0
            return
        with open(fi.full_name, "rb") as f:
            data = f.read()
        if not data:
            fi.entropy = 0.0
            return
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for c in counts.values():
            p = c / length
            entropy -= p * math.log2(p)
        fi.entropy = round(entropy, 2)


class MLScoreStage(VSPipelineStage):
    priority = 40

    def process(self, fi: VSFileInfo) -> None:
        score = 0.1
        if not fi.is_signed:
            score += 0.25
        if fi.entropy > 7.2:
            score += 0.35
        if fi.entropy > 7.8:
            score += 0.15
        if fi.last_write_time_utc:
            from datetime import datetime, timezone
            age_h = (datetime.now(timezone.utc) - fi.last_write_time_utc).total_seconds() / 3600
            if age_h < 24:
                score += 0.1
        name = fi.full_name.lower()
        if any(name.endswith(ext) for ext in (".so", ".elf", ".bin", ".sh", ".py", ".exe")):
            score += 0.05
        fi.ml_score = min(1.0, round(score, 3))


class RemoteReputationStage(VSPipelineStage):
    priority = 50

    def process(self, fi: VSFileInfo) -> None:
        if not fi.hash_sha256:
            return
        h = fi.hash_sha256
        if h in self.ctx.cache.remote:
            fi.remote_reputation = self.ctx.cache.remote[h]
            return
        api_key = os.environ.get("VS_VT_APIKEY")
        if not api_key:
            fi.remote_reputation = None
            return
        try:
            import json
            import urllib.request
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/files/{h}",
                headers={"x-apikey": api_key},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
            stats = data["data"]["attributes"]["last_analysis_stats"]
            mal = float(stats.get("malicious", 0))
            total = mal + float(stats.get("harmless", 0)) + float(stats.get("suspicious", 0)) + float(
                stats.get("undetected", 0)
            )
            rep = round(mal / total, 3) if total > 0 else 0.0
            fi.remote_reputation = rep
            self.ctx.cache.remote[h] = rep
        except Exception:
            fi.remote_reputation = None


STAGE_CLASSES = [
    HashStage,
    SignatureStage,
    EntropyStage,
    MLScoreStage,
    RemoteReputationStage,
]
