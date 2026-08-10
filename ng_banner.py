#!/usr/bin/env python3
"""Lightweight service banner / HTTP fingerprinting."""

from __future__ import annotations

import re
import socket
import ssl
from typing import Dict, Optional


def grab_banner(ip: str, port: int, timeout: float = 1.2) -> Dict[str, str]:
    """Return dict with banner/server/hint fields."""
    out = {"ip": ip, "port": str(port), "banner": "", "server": "", "hint": ""}
    try:
        if port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    req = (
                        f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    ).encode()
                    ssock.sendall(req)
                    data = ssock.recv(1024).decode("utf-8", "ignore")
                    out["banner"] = data.split("\r\n\r\n")[0][:500]
                    m = re.search(r"(?im)^Server:\s*(.+)$", data)
                    if m:
                        out["server"] = m.group(1).strip()
                    out["hint"] = "TLS/HTTPS service"
                    # cert subject
                    try:
                        cert = ssock.getpeercert()
                        if cert:
                            subj = cert.get("subject") or ()
                            cn = ""
                            for tup in subj:
                                for k, v in tup:
                                    if k == "commonName":
                                        cn = v
                            out["hint"] = f"TLS cert CN={cn or 'unknown'}"
                    except Exception:
                        pass
            return out

        if port in (80, 8000, 8080, 8888, 5000, 9000, 8060):
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                path = "/query/device-info" if port == 8060 else "/"
                req = (
                    f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                ).encode()
                sock.sendall(req)
                data = sock.recv(2048).decode("utf-8", "ignore")
                out["banner"] = data.split("\r\n\r\n")[0][:500]
                m = re.search(r"(?im)^Server:\s*(.+)$", data)
                if m:
                    out["server"] = m.group(1).strip()
                if port == 8060 and "roku" in data.lower():
                    out["hint"] = "Roku ECP"
                elif "HTTP/" in data:
                    out["hint"] = "HTTP service"
            return out

        if port in (22, 2222):
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                data = sock.recv(256).decode("utf-8", "ignore")
                out["banner"] = data.strip()[:200]
                out["hint"] = "SSH"
            return out

        if port == 23:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                data = sock.recv(256).decode("utf-8", "ignore")
                out["banner"] = data.strip()[:200]
                out["hint"] = "Telnet"
            return out

        # generic
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
                out["banner"] = data.decode("utf-8", "ignore").strip()[:200]
            except socket.timeout:
                out["hint"] = "open (no banner)"
    except Exception as exc:
        out["hint"] = f"probe failed: {exc}"
    return out
