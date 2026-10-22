#!/usr/bin/env python3
"""VectorStryke — Anti-Ransomware (Linux). Modular core under vs_core/."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vs_core.engine import Engine
from vs_core import __version__


def engine() -> Engine:
    return Engine(ROOT)


def cmd_status(eng: Engine) -> None:
    eng.reload()
    st = {}
    if eng.paths.status_file.exists():
        try:
            st = json.loads(eng.paths.status_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    running = eng.is_running()
    print("=== VECTORSTRYKE STATUS ===")
    print(f"  Version      : {eng.config.get('Version') or __version__}")
    print(f"  ResponseMode : {eng.config.get('ResponseMode') or 'Automatic'}")
    print(f"  Status       : {'ONLINE' if running else 'STOPPED'}")
    print(f"  Profile      : {eng.config.get('Profile')}")
    print(f"  FirstRun     : {eng.config.get('FirstRunState')}")
    print(f"  AgentId      : {eng.config.get('AgentId')}")
    if st:
        print(f"  Engine Mode  : {st.get('Mode')}")
        print(f"  Findings     : {st.get('FindingsCount')}")


def main() -> None:
    args = sys.argv[1:] or ["help"]
    cmd = args[0].lower()
    eng = engine()
    if cmd == "status":
        cmd_status(eng)
    elif cmd == "start":
        eng.start()
    elif cmd == "stop":
        eng.stop()
    elif cmd == "install":
        eng.paths.ensure()
        eng.ensure_agent_id()
        print("Installed. Run: python3 vectorstryke.py start")
    elif cmd == "scan":
        print(json.dumps(eng.scan_once(), indent=2, default=str))
    elif cmd == "health":
        print(json.dumps(eng.self_health(), indent=2, default=str))
    elif cmd == "mode":
        if len(args) < 2:
            print(eng.config.get("ResponseMode") or "Automatic")
        else:
            m = "Automatic" if args[1].lower() in ("automatic", "auto") else "Manual"
            eng.config_mgr.set_mode(m)
            print(f"ResponseMode={m}")
    else:
        print("Usage: vectorstryke.py start|stop|status|install|scan|health|mode")


if __name__ == "__main__":
    main()
