#!/usr/bin/env python3
"""Traffic summary helpers (top talkers) for Network Guard."""

from __future__ import annotations

import platform
import subprocess
from collections import Counter
from typing import Dict, List, Tuple


def top_talkers_windows(limit: int = 15) -> List[Dict[str, object]]:
    """Approximate top remote peers from active TCP connections."""
    ps = (
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
        "Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch '^(127\\.|::1)' } | "
        "Group-Object RemoteAddress | Sort-Object Count -Descending | "
        "Select-Object -First %d @{N='ip';E={$_.Name}},@{N='connections';E={$_.Count}} | "
        "ConvertTo-Json -Compress"
    ) % limit
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=25,
        )
        if proc.returncode != 0 or not (proc.stdout or "").strip():
            return []
        import json

        data = json.loads(proc.stdout)
        if isinstance(data, dict):
            data = [data]
        return [{"ip": d.get("ip"), "connections": int(d.get("connections") or 0)} for d in data]
    except Exception:
        return []


def top_talkers_linux(limit: int = 15) -> List[Dict[str, object]]:
    counts: Counter[str] = Counter()
    try:
        proc = subprocess.run(["ss", "-tn"], capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return []
        for line in proc.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            peer = parts[4]
            ip = peer.rsplit(":", 1)[0].strip("[]")
            if ip.startswith("127.") or ip in ("*", "::1"):
                continue
            counts[ip] += 1
    except Exception:
        return []
    return [{"ip": ip, "connections": n} for ip, n in counts.most_common(limit)]


def top_talkers(limit: int = 15) -> List[Dict[str, object]]:
    if platform.system().lower() == "windows":
        return top_talkers_windows(limit)
    return top_talkers_linux(limit)


def format_top_talkers(rows: List[Dict[str, object]]) -> str:
    if not rows:
        return "(no established remote peers)"
    lines = [f"  {r.get('ip'):<40} {r.get('connections')} conn(s)" for r in rows]
    return "\n".join(lines)
