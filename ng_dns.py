#!/usr/bin/env python3
"""DNS cache pairing helpers (Windows Get-DnsClientCache / Linux resolvectl)."""

from __future__ import annotations

import platform
import re
import subprocess
from typing import Dict, Optional


def dns_cache_map() -> Dict[str, str]:
    """Return remote-ip -> hostname from local DNS cache (best effort)."""
    system = platform.system().lower()
    out: Dict[str, str] = {}
    if system == "windows":
        ps = (
            "Get-DnsClientCache -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Data -and $_.Entry } | "
            "Select-Object Entry,Data | ConvertTo-Json -Compress"
        )
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if proc.returncode != 0 or not (proc.stdout or "").strip():
                return out
            import json

            data = json.loads(proc.stdout)
            if isinstance(data, dict):
                data = [data]
            for row in data:
                entry = str(row.get("Entry") or "").strip()
                ip = str(row.get("Data") or "").strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and entry:
                    out.setdefault(ip, entry)
        except Exception:
            return out
        return out
    # Linux: try resolvectl
    try:
        proc = subprocess.run(
            ["resolvectl", "query", "--cache"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Not always available; ignore
        _ = proc
    except Exception:
        pass
    return out


def lookup_cached_name(ip: str, cache: Optional[Dict[str, str]] = None) -> str:
    cache = cache if cache is not None else dns_cache_map()
    return cache.get(ip, "")
