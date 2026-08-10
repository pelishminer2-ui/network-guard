#!/usr/bin/env python3
"""Firewall action tracking: temp blocks, undo tokens, isolate markers."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
ACTIONS_FILE = SCRIPT_DIR / "firewall_actions.json"


def _load() -> List[Dict[str, Any]]:
    if not ACTIONS_FILE.exists():
        return []
    try:
        data = json.loads(ACTIONS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save(rows: List[Dict[str, Any]]) -> None:
    ACTIONS_FILE.write_text(json.dumps(rows[-200:], indent=2), encoding="utf-8")


def track_block(
    ip: str,
    rule_names: List[str],
    *,
    temp_minutes: int = 0,
    kind: str = "block",
) -> str:
    token = f"{kind}-{ip}-{int(time.time())}"
    rows = _load()
    rows.append(
        {
            "token": token,
            "ip": ip,
            "kind": kind,
            "rules": rule_names,
            "ts": time.time(),
            "expires": (time.time() + temp_minutes * 60) if temp_minutes > 0 else 0,
        }
    )
    _save(rows)
    return token


def list_actions() -> List[Dict[str, Any]]:
    return list(reversed(_load()))


def pop_last() -> Optional[Dict[str, Any]]:
    rows = _load()
    if not rows:
        return None
    last = rows.pop()
    _save(rows)
    return last


def expired_actions(now: Optional[float] = None) -> List[Dict[str, Any]]:
    now = now or time.time()
    return [r for r in _load() if r.get("expires") and r["expires"] <= now]


def pop_expired(now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Remove and return expired tracked actions."""
    now = now or time.time()
    rows = _load()
    keep: List[Dict[str, Any]] = []
    expired: List[Dict[str, Any]] = []
    for r in rows:
        if r.get("expires") and r["expires"] <= now:
            expired.append(r)
        else:
            keep.append(r)
    if expired:
        _save(keep)
    return expired


def windows_rule_names(ip: str, prefix: str = "NetworkGuard") -> List[str]:
    base = f"{prefix}-Block-{ip.replace(':', '-')}"
    return [f"{base}-In", f"{base}-Out"]


def windows_isolate_rule_names(ip: str, prefix: str = "NetworkGuard") -> List[str]:
    base = f"{prefix}-Isolate-{ip.replace(':', '-')}"
    return [f"{base}-In", f"{base}-Out", f"{base}-Lan"]
