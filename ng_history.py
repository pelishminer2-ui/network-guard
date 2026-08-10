#!/usr/bin/env python3
"""SQLite history + baseline for Network Guard."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent


def db_path(name: str = "history.db") -> Path:
    p = Path(name)
    return p if p.is_absolute() else SCRIPT_DIR / p


@contextmanager
def connect(name: str = "history.db") -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(str(db_path(name)))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                hostname TEXT,
                vendor TEXT,
                first_seen REAL,
                last_seen REAL,
                open_ports TEXT,
                notes TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                ip TEXT,
                proto TEXT,
                ports TEXT,
                reasons TEXT,
                action TEXT,
                detail TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                action TEXT,
                ip TEXT,
                detail TEXT,
                undo_token TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS baseline (
                ip TEXT PRIMARY KEY,
                ports TEXT,
                saved_at REAL
            )
            """
        )
        conn.commit()
        yield conn
    finally:
        conn.close()


def upsert_host(
    ip: str,
    mac: str = "",
    hostname: str = "",
    vendor: str = "",
    open_ports: Optional[List[int]] = None,
    db_name: str = "history.db",
) -> Dict[str, Any]:
    now = time.time()
    ports_s = json.dumps(sorted(open_ports or []))
    with connect(db_name) as conn:
        row = conn.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
        is_new = row is None
        if is_new:
            conn.execute(
                "INSERT INTO hosts(ip,mac,hostname,vendor,first_seen,last_seen,open_ports,notes) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (ip, mac, hostname, vendor, now, now, ports_s, ""),
            )
        else:
            conn.execute(
                "UPDATE hosts SET mac=COALESCE(NULLIF(?,''),mac), "
                "hostname=COALESCE(NULLIF(?,''),hostname), "
                "vendor=COALESCE(NULLIF(?,''),vendor), "
                "last_seen=?, open_ports=? WHERE ip=?",
                (mac, hostname, vendor, now, ports_s, ip),
            )
        conn.commit()
        return {"ip": ip, "is_new": is_new, "first_seen": row["first_seen"] if row else now}


def record_finding(
    ip: str,
    proto: str,
    ports: List[int],
    reasons: List[str],
    action: str = "",
    detail: str = "",
    db_name: str = "history.db",
) -> None:
    with connect(db_name) as conn:
        conn.execute(
            "INSERT INTO findings(ts,ip,proto,ports,reasons,action,detail) VALUES(?,?,?,?,?,?,?)",
            (
                time.time(),
                ip,
                proto,
                json.dumps(ports),
                json.dumps(reasons),
                action,
                detail,
            ),
        )
        conn.commit()


def record_action(
    action: str,
    ip: str,
    detail: str = "",
    undo_token: str = "",
    db_name: str = "history.db",
) -> int:
    with connect(db_name) as conn:
        cur = conn.execute(
            "INSERT INTO actions(ts,action,ip,detail,undo_token) VALUES(?,?,?,?,?)",
            (time.time(), action, ip, detail, undo_token),
        )
        conn.commit()
        return int(cur.lastrowid)


def last_actions(limit: int = 20, db_name: str = "history.db") -> List[Dict[str, Any]]:
    with connect(db_name) as conn:
        rows = conn.execute(
            "SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def recent_findings(limit: int = 50, db_name: str = "history.db") -> List[Dict[str, Any]]:
    with connect(db_name) as conn:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def all_hosts(db_name: str = "history.db") -> List[Dict[str, Any]]:
    with connect(db_name) as conn:
        rows = conn.execute(
            "SELECT * FROM hosts ORDER BY last_seen DESC"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["open_ports"] = json.loads(d.get("open_ports") or "[]")
            except json.JSONDecodeError:
                d["open_ports"] = []
            out.append(d)
        return out


def save_baseline(hosts: List[Dict[str, Any]], db_name: str = "history.db") -> int:
    now = time.time()
    with connect(db_name) as conn:
        n = 0
        for h in hosts:
            ip = h.get("ip")
            if not ip:
                continue
            ports = h.get("open_ports") or []
            conn.execute(
                "INSERT OR REPLACE INTO baseline(ip,ports,saved_at) VALUES(?,?,?)",
                (ip, json.dumps(sorted(ports)), now),
            )
            n += 1
        conn.commit()
        return n


def baseline_map(db_name: str = "history.db") -> Dict[str, List[int]]:
    with connect(db_name) as conn:
        rows = conn.execute("SELECT ip, ports FROM baseline").fetchall()
        out: Dict[str, List[int]] = {}
        for r in rows:
            try:
                out[r["ip"]] = json.loads(r["ports"] or "[]")
            except json.JSONDecodeError:
                out[r["ip"]] = []
        return out


def new_ports_vs_baseline(ip: str, ports: List[int], db_name: str = "history.db") -> List[int]:
    base = baseline_map(db_name).get(ip)
    if base is None:
        return []  # no baseline yet = don't treat as regression
    return sorted(set(ports) - set(base))
