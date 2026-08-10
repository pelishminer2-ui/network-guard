#!/usr/bin/env python3
"""
Network Guard Dashboard — local web command center.
Author: Pilisi W — 2026

Run: python ng_dashboard.py
Or:  run_dashboard.bat
"""

from __future__ import annotations

import json
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from ng_config import load_config  # noqa: E402
from ng_history import (  # noqa: E402
    all_hosts,
    last_actions,
    recent_findings,
    save_baseline,
    upsert_host,
)
from ng_notify import notify  # noqa: E402
from ng_oui import label_device, vendor_from_mac  # noqa: E402
from ng_report import write_incident_report  # noqa: E402

STATE: Dict[str, Any] = {
    "scanning": False,
    "last_scan": None,
    "findings": [],
    "lan_hosts": [],
    "error": "",
}


def _json(handler: BaseHTTPRequestHandler, code: int, payload: Any) -> None:
    body = json.dumps(payload, default=str).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def run_scan(quick: bool = False) -> None:
    import network_guard as ng

    STATE["scanning"] = True
    STATE["error"] = ""
    try:
        cfg = load_config()
        allowlist = ng.load_ip_list(ng.DEFAULT_ALLOWLIST)
        blocklist = ng.load_ip_list(ng.DEFAULT_BLOCKLIST)
        # reputation list
        rep = SCRIPT_DIR / str(cfg.get("reputation_blocklist") or "reputation_blocklist.txt")
        if rep.exists():
            blocklist |= ng.load_ip_list(rep)

        network = ng.guess_subnet(cfg.get("subnet"))
        log_path = ng.DEFAULT_LOG
        ng.log("DASHBOARD scan starting...", log_path)

        findings = []
        conns = ng.enumerate_connections()
        findings.extend(
            ng.enrich_and_detect(
                conns, allowlist, blocklist, allow_state=ng.load_allow_state(), log_path=log_path
            )
        )

        ports = (
            tuple(cfg.get("quick_ports") or list(ng.LAN_PROBE_PORTS))
            if quick
            else ng.LAN_PROBE_PORTS
        )
        lan_hosts = ng.scan_lan(
            network,
            allowlist,
            blocklist,
            log_path,
            workers=max(8, int(cfg.get("lan_workers") or 48)),
            port_timeout=float(cfg.get("lan_port_timeout") or 0.35),
            ports=ports,
            allow_state=ng.load_allow_state(),
        )

        # enrich labels + history
        host_dicts = []
        new_devices = []
        for h in lan_hosts:
            vendor = vendor_from_mac(h.mac)
            label = label_device(h.hostname, h.mac, h.hostname or vendor)
            if vendor and (not h.hostname or h.hostname == "-"):
                h.hostname = vendor
            elif label and not h.hostname:
                h.hostname = label
            info = upsert_host(
                h.ip,
                mac=h.mac,
                hostname=h.hostname,
                vendor=vendor,
                open_ports=h.open_ports,
                db_name=str(cfg.get("history_db") or "history.db"),
            )
            if info.get("is_new"):
                new_devices.append(h.ip)
            host_dicts.append(
                {
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "mac": h.mac,
                    "vendor": vendor,
                    "open_ports": h.open_ports,
                    "reasons": h.reasons,
                    "is_gateway": h.is_gateway,
                    "suspicious": h.suspicious,
                }
            )

        finding_dicts = []
        for f in findings + ng.lan_hosts_to_findings(lan_hosts):
            finding_dicts.append(
                {
                    "ip": f.remote_ip,
                    "proto": f.proto,
                    "ports": [f.remote_port] if f.remote_port else [],
                    "reasons": f.reasons,
                    "process": f.process_name,
                    "pid": f.pid,
                }
            )
            from ng_history import record_finding

            record_finding(
                f.remote_ip,
                f.proto,
                [f.remote_port] if f.remote_port else [],
                f.reasons,
                db_name=str(cfg.get("history_db") or "history.db"),
            )

        STATE["findings"] = finding_dicts
        STATE["lan_hosts"] = host_dicts
        STATE["last_scan"] = time.time()

        if new_devices and cfg.get("notify_on_new_device", True):
            notify(
                "Network Guard — new device(s)",
                ", ".join(new_devices[:5]),
            )
    except Exception as exc:
        STATE["error"] = str(exc)
        traceback.print_exc()
    finally:
        STATE["scanning"] = False


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Network Guard Command Center</title>
<style>
:root{--bg:#0b0f14;--panel:#121821;--line:#243041;--text:#e8eef7;--muted:#93a0b4;--accent:#3b82f6;--good:#34d399;--bad:#f87171;--warn:#fbbf24}
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,system-ui,sans-serif;background:radial-gradient(1200px 600px at 10% -10%,#1a2740,transparent),var(--bg);color:var(--text)}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 22px;border-bottom:1px solid var(--line);background:rgba(0,0,0,.25);position:sticky;top:0;backdrop-filter:blur(8px);z-index:5}
h1{margin:0;font-size:20px;letter-spacing:.02em}
.sub{color:var(--muted);font-size:12px}
.btns{display:flex;gap:8px;flex-wrap:wrap}
button,.btn{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:8px 12px;font-weight:600;cursor:pointer}
button.secondary{background:#1f2a3a;border:1px solid var(--line)}
button.danger{background:#b91c1c}
main{display:grid;grid-template-columns:1.2fr .8fr;gap:14px;padding:14px}
@media(max-width:1100px){main{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px;min-height:120px}
.card h2{margin:0 0 10px;font-size:14px;color:#c7d2fe;text-transform:uppercase;letter-spacing:.08em}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
.badge.bad{background:#3f1212;color:var(--bad)}
.badge.ok{background:#0f2e22;color:var(--good)}
.badge.warn{background:#3a2e0b;color:var(--warn)}
#status{font-size:13px;color:var(--muted)}
.mono{font-family:Consolas,ui-monospace,monospace;font-size:12px}
.row-actions button{padding:4px 8px;font-size:11px;margin-right:4px}
input[type=text]{background:#0d1420;border:1px solid var(--line);color:var(--text);border-radius:8px;padding:8px;width:100%}
</style>
</head>
<body>
<header>
  <div>
    <h1>Network Guard Command Center</h1>
    <div class="sub">Pilisi W · 2026 · local-only dashboard (127.0.0.1)</div>
  </div>
  <div class="btns">
    <button onclick="scan(false)">Full Scan</button>
    <button class="secondary" onclick="scan(true)">Quick Scan</button>
    <button class="secondary" onclick="baseline()">Save Baseline</button>
    <button class="secondary" onclick="undo()">Undo Last Block</button>
    <button class="secondary" onclick="report()">Export Report</button>
    <button class="secondary" onclick="selftest()">Self-Test</button>
  </div>
</header>
<main>
  <section class="card">
    <h2>LAN Map</h2>
    <div id="status">Ready.</div>
    <div style="overflow:auto;max-height:62vh;margin-top:8px">
      <table>
        <thead><tr><th>IP</th><th>Device</th><th>Vendor</th><th>Ports</th><th>Flags</th><th>Actions</th></tr></thead>
        <tbody id="hosts"></tbody>
      </table>
    </div>
  </section>
  <section class="card">
    <h2>Findings</h2>
    <div style="overflow:auto;max-height:34vh">
      <table>
        <thead><tr><th>IP</th><th>Why</th><th>Act</th></tr></thead>
        <tbody id="findings"></tbody>
      </table>
    </div>
    <h2 style="margin-top:16px">Recent Actions</h2>
    <div style="overflow:auto;max-height:22vh">
      <table>
        <thead><tr><th>When</th><th>Action</th><th>IP</th></tr></thead>
        <tbody id="actions"></tbody>
      </table>
    </div>
    <h2 style="margin-top:16px">Roku / Device Probe</h2>
    <div style="display:flex;gap:8px">
      <input id="rokuIp" type="text" placeholder="192.168.1.102"/>
      <button class="secondary" onclick="roku()">Open Status</button>
    </div>
    <pre id="rokuOut" class="mono" style="white-space:pre-wrap;color:var(--muted)"></pre>
  </section>
</main>
<script>
async function api(path, opts){
  const r = await fetch(path, opts||{});
  return r.json();
}
function esc(s){return (s??'').toString().replace(/[&<>]/g,c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c]));}
async function refresh(){
  const s = await api('/api/state');
  document.getElementById('status').textContent = s.scanning
    ? 'Scanning…' : (`Last scan: ${s.last_scan? new Date(s.last_scan*1000).toLocaleString():'never'}` + (s.error? ' | ERROR '+s.error:''));
  const hb = document.getElementById('hosts');
  hb.innerHTML = (s.lan_hosts||[]).map(h=>`<tr>
    <td class="mono">${esc(h.ip)}</td>
    <td>${esc(h.hostname||'-')}</td>
    <td>${esc(h.vendor||'-')}</td>
    <td class="mono">${esc((h.open_ports||[]).join(', ')||'-')}</td>
    <td>${h.suspicious?'<span class="badge bad">SUSPICIOUS</span>':(h.is_gateway?'<span class="badge warn">gateway</span>':'<span class="badge ok">ok</span>')}</td>
    <td class="row-actions">
      <button class="secondary" onclick="blockIp('${esc(h.ip)}')">Block</button>
      <button class="secondary" onclick="allowIp('${esc(h.ip)}')">Allow</button>
      <button class="secondary" onclick="tempBlock('${esc(h.ip)}')">Temp</button>
    </td></tr>`).join('') || '<tr><td colspan="6">No hosts yet — run a scan.</td></tr>';
  document.getElementById('findings').innerHTML = (s.findings||[]).map(f=>`<tr>
    <td class="mono">${esc(f.ip)}</td>
    <td>${esc((f.reasons||[]).join('; '))}</td>
    <td class="row-actions">
      <button class="danger" onclick="blockIp('${esc(f.ip)}')">Block</button>
      <button class="secondary" onclick="allowIp('${esc(f.ip)}')">Allow</button>
    </td></tr>`).join('') || '<tr><td colspan="3">No findings.</td></tr>';
  const acts = await api('/api/actions');
  document.getElementById('actions').innerHTML = (acts.actions||[]).map(a=>`<tr>
    <td>${esc(new Date((a.ts||0)*1000).toLocaleString())}</td>
    <td>${esc(a.action)}</td><td class="mono">${esc(a.ip)}</td></tr>`).join('') || '<tr><td colspan="3">None</td></tr>';
}
async function scan(quick){
  document.getElementById('status').textContent='Scan started…';
  await api('/api/scan?quick='+(quick?'1':'0'), {method:'POST'});
  for(let i=0;i<120;i++){ await new Promise(r=>setTimeout(r,1000)); const s=await api('/api/state'); if(!s.scanning) break; }
  await refresh();
}
async function blockIp(ip){ await api('/api/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip, temp:false})}); await refresh(); }
async function tempBlock(ip){ await api('/api/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip, temp:true})}); await refresh(); }
async function allowIp(ip){ await api('/api/allow',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); await refresh(); }
async function undo(){ const r=await api('/api/undo',{method:'POST'}); alert(r.message||JSON.stringify(r)); await refresh(); }
async function baseline(){ const r=await api('/api/baseline',{method:'POST'}); alert('Baseline saved for '+r.count+' hosts'); }
async function report(){ const r=await api('/api/report',{method:'POST'}); if(r.path){ window.open('/reports/'+r.path.split(/[/\\\\]/).pop(),'_blank'); alert('Report: '+r.path);} }
async function selftest(){ const r=await api('/api/selftest'); document.getElementById('rokuOut').textContent=JSON.stringify(r,null,2); }
async function roku(){
  const ip=document.getElementById('rokuIp').value.trim();
  const r=await api('/api/roku?ip='+encodeURIComponent(ip));
  document.getElementById('rokuOut').textContent=JSON.stringify(r,null,2);
  if(r.page) window.open(r.page,'_blank');
}
refresh(); setInterval(refresh, 5000);
</script>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write("[dash] " + (fmt % args) + "\n")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/state":
            _json(
                self,
                200,
                {
                    "scanning": STATE["scanning"],
                    "last_scan": STATE["last_scan"],
                    "findings": STATE["findings"],
                    "lan_hosts": STATE["lan_hosts"],
                    "error": STATE["error"],
                },
            )
            return

        if path == "/api/actions":
            cfg = load_config()
            _json(
                self,
                200,
                {
                    "actions": last_actions(30, str(cfg.get("history_db") or "history.db")),
                    "hosts_history": all_hosts(str(cfg.get("history_db") or "history.db"))[:100],
                    "findings_history": recent_findings(
                        40, str(cfg.get("history_db") or "history.db")
                    ),
                },
            )
            return

        if path == "/api/roku":
            import network_guard as ng

            ip = (qs.get("ip") or [""])[0].strip()
            if not ip:
                _json(self, 400, {"error": "ip required"})
                return
            ok = ng.open_roku_visual_status(ip, "ROKU", ng.DEFAULT_LOG)
            st = ng.fetch_roku_status(ip)
            page = ""
            p = ng.UI_CAPTURE_DIR / f"roku_{ip.replace('.', '_')}_status.html"
            if p.exists():
                page = "/captures/" + p.name
            _json(
                self,
                200,
                {
                    "ok": ok,
                    "status": {k: v for k, v in st.items() if k != "icon_bytes"},
                    "page": page,
                },
            )
            return

        if path == "/api/selftest":
            _json(self, 200, self_test())
            return

        if path.startswith("/captures/"):
            name = path.split("/")[-1]
            fp = SCRIPT_DIR / "ui_captures" / name
            return self._file(fp)

        if path.startswith("/reports/"):
            name = path.split("/")[-1]
            fp = SCRIPT_DIR / "reports" / name
            return self._file(fp)

        _json(self, 404, {"error": "not found"})

    def _file(self, fp: Path) -> None:
        if not fp.exists() or not fp.is_file():
            _json(self, 404, {"error": "missing"})
            return
        data = fp.read_bytes()
        ctype = "text/html" if fp.suffix == ".html" else "application/octet-stream"
        if fp.suffix == ".png":
            ctype = "image/png"
        if fp.suffix in (".jpg", ".jpeg"):
            ctype = "image/jpeg"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            body = {}

        if path == "/api/scan":
            if STATE["scanning"]:
                _json(self, 409, {"error": "already scanning"})
                return
            quick = (qs.get("quick") or ["0"])[0] == "1" or body.get("quick")
            threading.Thread(target=run_scan, kwargs={"quick": quick}, daemon=True).start()
            _json(self, 200, {"ok": True})
            return

        if path == "/api/block":
            import network_guard as ng

            ip = body.get("ip", "").strip()
            temp = bool(body.get("temp"))
            cfg = load_config()
            minutes = int(cfg.get("temp_block_minutes") or 60) if temp else 0
            ok = ng.block_ip(
                ip,
                dry_run=False,
                log_path=ng.DEFAULT_LOG,
                allow_private=ng.is_private_lan(ip),
                protected=set(ng.local_ipv4_addrs())
                | ({ng.default_gateway()} if ng.default_gateway() else set()),
                temp_minutes=minutes,
            )
            if ok:
                ng.append_blocklist(ip, ng.DEFAULT_BLOCKLIST)
                notify("Network Guard blocked", ip)
            _json(self, 200, {"ok": ok, "temp_minutes": minutes})
            return

        if path == "/api/allow":
            import network_guard as ng
            from ng_history import record_action

            ip = body.get("ip", "").strip()
            ng.append_allowlist(ip, ng.DEFAULT_ALLOWLIST, device_name=body.get("name") or "")
            cfg = load_config()
            record_action(
                "allow",
                ip,
                db_name=str(cfg.get("history_db") or "history.db"),
            )
            _json(self, 200, {"ok": True})
            return

        if path == "/api/undo":
            msg = undo_last_block()
            _json(self, 200, {"message": msg})
            return

        if path == "/api/baseline":
            cfg = load_config()
            count = save_baseline(
                STATE.get("lan_hosts") or [],
                db_name=str(cfg.get("history_db") or "history.db"),
            )
            _json(self, 200, {"count": count})
            return

        if path == "/api/report":
            cfg = load_config()
            path_out = write_incident_report(
                findings=STATE.get("findings") or [],
                lan_hosts=STATE.get("lan_hosts") or [],
                actions=last_actions(50, str(cfg.get("history_db") or "history.db")),
            )
            _json(self, 200, {"path": str(path_out)})
            return

        _json(self, 404, {"error": "not found"})


def undo_last_block() -> str:
    import network_guard as ng
    from ng_firewall_ext import pop_last
    from ng_history import record_action

    last = pop_last()
    if not last:
        return "No tracked firewall action to undo."
    ip = last.get("ip")
    removed = 0
    if ng.is_windows():
        for name in last.get("rules") or []:
            code, _, _ = ng.run_cmd(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
            )
            if code == 0:
                removed += 1
    else:
        # best-effort message
        removed = -1
    cfg = load_config()
    record_action(
        "undo",
        ip or "",
        detail=json.dumps(last),
        db_name=str(cfg.get("history_db") or "history.db"),
    )
    return f"Undo {last.get('kind')} for {ip}: removed ~{removed} rule(s)."


def self_test() -> Dict[str, Any]:
    import network_guard as ng

    cfg = load_config()
    checks: Dict[str, Any] = {
        "python": sys.version,
        "admin": ng.is_admin(),
        "platform": f"{ng.platform.system()} {ng.platform.release()}",
        "allowlist_exists": ng.DEFAULT_ALLOWLIST.exists(),
        "blocklist_exists": ng.DEFAULT_BLOCKLIST.exists(),
        "devices_exists": ng.DEFAULT_DEVICES.exists(),
        "config_example": (SCRIPT_DIR / "config.example.yaml").exists(),
        "history_db": str(cfg.get("history_db")),
        "gateway": ng.default_gateway(),
        "local_ips": ng.local_ipv4_addrs(),
        "pillow": False,
        "agent_token": (SCRIPT_DIR / "agent_token.txt").exists(),
        "firewall_actions_file": (SCRIPT_DIR / "firewall_actions.json").exists(),
        "modules": {},
    }
    try:
        checks["subnet"] = str(ng.guess_subnet(cfg.get("subnet")))
    except Exception as exc:
        checks["subnet"] = f"error: {exc}"
    try:
        import PIL  # noqa: F401

        checks["pillow"] = True
    except Exception:
        checks["pillow"] = False
    for mod in (
        "ng_oui",
        "ng_history",
        "ng_profiles",
        "ng_banner",
        "ng_firewall_ext",
        "ng_router",
        "ng_traffic",
        "ng_cert",
        "ng_report",
        "ng_notify",
        "ng_config",
        "ng_dns",
    ):
        try:
            __import__(mod)
            checks["modules"][mod] = "ok"
        except Exception as exc:
            checks["modules"][mod] = f"fail: {exc}"
    return checks


def main() -> int:
    cfg = load_config()
    port = int(cfg.get("dashboard_port") or 8765)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print("=" * 60)
    print(" Network Guard Command Center")
    print(f" Open: {url}")
    print(" Pilisi W · 2026 · local only")
    print("=" * 60)
    try:
        import webbrowser

        webbrowser.open(url, new=2)
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
