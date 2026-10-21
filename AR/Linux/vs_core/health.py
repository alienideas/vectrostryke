"""Self-health checks."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .base import Component


class HealthChecker(Component):
    def run(self) -> dict:
        issues = []
        ok = True
        for label, p in (
            ("ROOT", self._paths.root),
            ("config", self._paths.config_dir),
            ("data", self._paths.data),
            ("logs", self._paths.logs),
            ("quarantine", self._paths.quarantine),
        ):
            if not p.exists():
                issues.append(f"missing_path:{label}")
                ok = False
        if not self._paths.config_file.exists():
            issues.append("missing_config")
            ok = False
        result = {
            "Ok": ok,
            "Version": self._config.get("Version") or "1.7.0",
            "Profile": self._config.get("Profile") or "Server",
            "FirstRunState": self._config.get("FirstRunState") or "PendingConfig",
            "ResponseMode": self._config.get("ResponseMode") or "Automatic",
            "Issues": issues,
            "CheckedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self._paths.health_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
