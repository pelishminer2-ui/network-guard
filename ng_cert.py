#!/usr/bin/env python3
"""Light HTTPS certificate sanity checks for LAN devices."""

from __future__ import annotations

import datetime as dt
import socket
import ssl
from typing import Any, Dict, List, Optional


def check_https_cert(ip: str, port: int = 443, timeout: float = 2.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ip": ip,
        "port": port,
        "ok": False,
        "cn": "",
        "issuer": "",
        "not_after": "",
        "warnings": [],
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                # With CERT_NONE, getpeercert() may be empty — use binary
                if not cert:
                    cert = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))
                    out["warnings"].append("certificate presented but details unavailable without verify")
                    out["ok"] = True
                    return out
                subj = cert.get("subject") or ()
                for tup in subj:
                    for k, v in tup:
                        if k == "commonName":
                            out["cn"] = v
                issuer = cert.get("issuer") or ()
                bits = []
                for tup in issuer:
                    for k, v in tup:
                        if k in ("organizationName", "commonName"):
                            bits.append(v)
                out["issuer"] = ", ".join(bits)
                na = cert.get("notAfter") or ""
                out["not_after"] = na
                if na:
                    try:
                        exp = dt.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - dt.datetime.utcnow()).days
                        if days < 0:
                            out["warnings"].append("certificate expired")
                        elif days < 14:
                            out["warnings"].append(f"certificate expires in {days} day(s)")
                    except ValueError:
                        pass
                # Self-signed / weird for LAN is common; warn if CN is empty or IP mismatch-ish
                if not out["cn"]:
                    out["warnings"].append("missing commonName")
                out["ok"] = True
    except Exception as exc:
        out["warnings"].append(str(exc))
    return out


def scan_lan_certs(hosts: List[Dict[str, Any]], ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    ports = ports or [443, 8443]
    results = []
    for h in hosts:
        ip = h.get("ip") if isinstance(h, dict) else getattr(h, "ip", None)
        open_ports = h.get("open_ports") if isinstance(h, dict) else getattr(h, "open_ports", [])
        if not ip:
            continue
        for p in ports:
            if p in (open_ports or []):
                results.append(check_https_cert(ip, p))
    return results
