#!/usr/bin/env python3
"""
Network Guard Agent — run this on OTHER Windows/Linux devices you own
so the main Network Guard console can view that device's screen UI.

Usage (on the device to monitor):
  python network_guard_agent.py
  or double-click run_network_guard_agent.bat

Then from your main PC, choose [U] View UI on a LAN finding for this IP.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
TOKEN_FILE = SCRIPT_DIR / "agent_token.txt"
DEFAULT_PORT = 38765


def load_or_create_token() -> str:
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_urlsafe(24)
    TOKEN_FILE.write_text(token + "\n", encoding="utf-8")
    return token


def capture_jpeg(quality: int = 55) -> bytes:
    try:
        from PIL import ImageGrab
    except ImportError as exc:
        raise RuntimeError("Pillow is required: pip install pillow") from exc
    img = ImageGrab.grab(all_screens=True)
    # Shrink large desktops for faster transfer
    max_w = 1600
    if img.width > max_w:
        ratio = max_w / float(img.width)
        img = img.resize((max_w, int(img.height * ratio)))
    buf = io.BytesIO()
    img.convert("RGB").save(buf, format="JPEG", quality=quality, optimize=True)
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description="Network Guard screen agent")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="Address to bind (default 0.0.0.0 = reachable on LAN)",
    )
    args = parser.parse_args()
    token = load_or_create_token()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *a) -> None:  # quieter
            sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % a))

        def _unauthorized(self) -> None:
            body = b'{"error":"unauthorized"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _token_ok(self) -> bool:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            qtok = (qs.get("token") or [""])[0]
            hdr = self.headers.get("X-NetworkGuard-Token", "")
            return secrets.compare_digest(qtok or hdr, token)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            if path == "/health":
                body = b'{"ok":true,"service":"network-guard-agent"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if not self._token_ok():
                self._unauthorized()
                return
            if path == "/info":
                payload = {
                    "ok": True,
                    "hostname": os.environ.get("COMPUTERNAME")
                    or os.environ.get("HOSTNAME")
                    or "unknown",
                    "user": os.environ.get("USERNAME")
                    or os.environ.get("USER")
                    or "",
                    "pid": os.getpid(),
                }
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/screenshot":
                try:
                    jpeg = capture_jpeg()
                except Exception as exc:  # noqa: BLE001
                    body = json.dumps({"error": str(exc)}).encode("utf-8")
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Length", str(len(jpeg)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(jpeg)
                return
            body = b'{"error":"not found"}'
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    print("=" * 60)
    print(" Network Guard Agent - screen sharing for YOUR devices")
    print("=" * 60)
    print(f" Listening on http://{args.bind}:{args.port}")
    print(f" Token file : {TOKEN_FILE}")
    print(f" Token      : {token}")
    print()
    print(" Copy agent_token.txt to your main Network Guard PC (same folder),")
    print(" or keep an identical token string in both places.")
    print(" Endpoints: /health  /info?token=...  /screenshot?token=...")
    print(" Press Ctrl+C to stop.")
    print("=" * 60)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nStopping agent...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    # Pillow import check early
    try:
        from PIL import ImageGrab  # noqa: F401
    except ImportError:
        print("ERROR: Pillow is required. Run: pip install pillow", file=sys.stderr)
        sys.exit(1)
    sys.exit(main())
