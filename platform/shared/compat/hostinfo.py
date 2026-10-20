"""Cross-platform host identity helpers (Windows / macOS / Linux)."""
from __future__ import annotations

import os
import platform
import socket
from typing import Tuple


def hostname() -> str:
    try:
        return socket.gethostname() or "unknown"
    except Exception:
        return platform.node() or "unknown"


def username() -> str:
    return (
        os.environ.get("USERNAME")
        or os.environ.get("USER")
        or os.environ.get("LOGNAME")
        or "unknown"
    )


def os_family() -> str:
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "macos"
    if s == "linux":
        return "linux"
    return s or "unknown"


def platform_tuple() -> Tuple[str, str, str]:
    return os_family(), hostname(), username()
