#!/usr/bin/env python3
"""HTML incident report generator."""

from __future__ import annotations

import datetime as dt
import html
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
REPORTS_DIR = SCRIPT_DIR / "reports"


def write_incident_report(
    *,
    findings: List[Dict[str, Any]],
    lan_hosts: List[Dict[str, Any]],
    actions: List[Dict[str, Any]],
    title: str = "Network Guard Incident Report",
) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"report_{stamp}.html"

    def esc(x: Any) -> str:
        return html.escape(str(x if x is not None else ""))

    finding_rows = ""
    for f in findings:
        finding_rows += (
            f"<tr><td>{esc(f.get('ip'))}</td><td>{esc(f.get('proto'))}</td>"
            f"<td>{esc(f.get('ports'))}</td><td>{esc(f.get('reasons'))}</td></tr>"
        )
    host_rows = ""
    for h in lan_hosts:
        host_rows += (
            f"<tr><td>{esc(h.get('ip'))}</td><td>{esc(h.get('hostname'))}</td>"
            f"<td>{esc(h.get('vendor'))}</td><td>{esc(h.get('mac'))}</td>"
            f"<td>{esc(h.get('open_ports'))}</td></tr>"
        )
    action_rows = ""
    for a in actions:
        action_rows += (
            f"<tr><td>{esc(a.get('ts'))}</td><td>{esc(a.get('action'))}</td>"
            f"<td>{esc(a.get('ip'))}</td><td>{esc(a.get('detail'))}</td></tr>"
        )

    doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>{esc(title)}</title>
<style>
body{{font-family:Segoe UI,system-ui,sans-serif;margin:24px;color:#1f2328;background:#fff}}
h1{{color:#0969da}} table{{border-collapse:collapse;width:100%;margin:12px 0 24px}}
th,td{{border:1px solid #d0d7de;padding:8px;text-align:left;font-size:13px}}
th{{background:#f6f8fa}} .meta{{color:#656d76;margin-bottom:18px}}
</style></head><body>
<h1>{esc(title)}</h1>
<div class="meta">Generated {esc(dt.datetime.now().isoformat(timespec='seconds'))} · Pilisi W · 2026</div>
<h2>Findings</h2>
<table><tr><th>IP</th><th>Proto</th><th>Ports</th><th>Reasons</th></tr>
{finding_rows or '<tr><td colspan="4">None</td></tr>'}
</table>
<h2>LAN hosts</h2>
<table><tr><th>IP</th><th>Hostname</th><th>Vendor</th><th>MAC</th><th>Ports</th></tr>
{host_rows or '<tr><td colspan="5">None</td></tr>'}
</table>
<h2>Actions</h2>
<table><tr><th>Time</th><th>Action</th><th>IP</th><th>Detail</th></tr>
{action_rows or '<tr><td colspan="4">None</td></tr>'}
</table>
</body></html>
"""
    path.write_text(doc, encoding="utf-8")
    return path
