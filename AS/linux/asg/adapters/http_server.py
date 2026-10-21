"""Production-oriented ASG HTTP server: /health, /v1/inspect (stdlib http.server)."""
from __future__ import annotations

import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

AS_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(AS_ROOT / "linux"))

from asg.adapters.rest import handle_message  # noqa: E402
from asg.pipeline.engine import ASGEngine  # noqa: E402

LOG = logging.getLogger("asg.http")


def load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ASGHandler(BaseHTTPRequestHandler):
    engine: ASGEngine = None  # type: ignore

    def _json(self, code: int, obj: Any) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/health", "/healthz"):
            self._json(200, {"status": "ok", "service": "asg", "version": "1.0.0"})
            return
        if path == "/ready":
            self._json(200, {"ready": True})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/v1/inspect":
            self._json(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid_json"})
            return
        try:
            result = handle_message(self.engine, payload)
            self._json(200, result)
        except Exception as e:
            LOG.exception("inspect failed")
            self._json(500, {"error": str(e)})


def serve(config_path: Path, root: Path, host: str = "127.0.0.1", port: int = 8787) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cfg = load_config(config_path)
    listen = cfg.get("listen") or {}
    host = listen.get("rest_host", host)
    port = int(listen.get("rest_port", port))
    engine = ASGEngine(cfg, root)
    ASGHandler.engine = engine
    httpd = ThreadingHTTPServer((host, port), ASGHandler)
    LOG.info(json.dumps({"event": "listen", "host": host, "port": port}))
    httpd.serve_forever()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(AS_ROOT / "config" / "asg.json"))
    ap.add_argument("--root", default=str(AS_ROOT))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    serve(Path(args.config), Path(args.root), args.host, args.port)
