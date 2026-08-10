#!/usr/bin/env python3
"""
Network Guard — detect suspicious network activity, block remote IPs,
optionally terminate offending processes, and scan other devices on
your local network for suspicious open ports.

Works on Windows and Linux (Python 3.7+). Requires administrator/root
for firewall changes and process termination.

LAN mode discovers hosts on your subnet and probes common backdoor
ports. Blocks applied here protect THIS machine; other devices stay
exposed unless you also block at the router/firewall.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import io
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Heuristics: common backdoor / reverse-shell / C2 ports and risky listeners
# ---------------------------------------------------------------------------
SUSPICIOUS_REMOTE_PORTS: Set[int] = {
    1337, 2222, 3333, 4444, 5555, 6666, 6667, 6668, 6669,
    7777, 8888, 9999, 12345, 31337, 1234, 4443, 8443,
    9050, 9051, 1080, 3128, 4899, 5900, 5901, 5800,
}

SUSPICIOUS_LISTEN_PORTS: Set[int] = {
    1337, 2222, 4444, 5555, 6666, 7777, 8888, 9999,
    12345, 31337, 4443, 4899,
}

# Ports probed on other LAN devices (keep tight for speed)
LAN_PROBE_PORTS: Tuple[int, ...] = tuple(
    sorted(
        SUSPICIOUS_LISTEN_PORTS
        | {23, 2323, 3389, 5555, 7547, 49152, 5000, 8000, 8080, 8443}
    )
)

SUSPICIOUS_PROCESS_NAMES: Set[str] = {
    "nc", "ncat", "netcat", "socat", "meterpreter",
    "mimikatz", "cobaltstrike", "beacon",
}

# Always skip these locals / specials
PRIVATE_SKIP_PREFIXES = (
    "127.", "::1", "0.0.0.0", "*",
)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = SCRIPT_DIR / "allowlist.txt"
DEFAULT_BLOCKLIST = SCRIPT_DIR / "blocklist.txt"
DEFAULT_DEVICES = SCRIPT_DIR / "devices.txt"
DEFAULT_ALLOW_STATE = SCRIPT_DIR / "allowlist_state.json"
DEFAULT_LOG = SCRIPT_DIR / "network_guard.log"
RULE_PREFIX = "NetworkGuard"


@dataclass
class Connection:
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    pid: Optional[int] = None
    process_name: str = ""
    reasons: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.proto}|{self.local_ip}:{self.local_port}|{self.remote_ip}:{self.remote_port}|{self.pid}"


@dataclass
class LanHost:
    ip: str
    hostname: str = ""
    mac: str = ""
    open_ports: List[int] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    is_gateway: bool = False
    is_self: bool = False

    @property
    def suspicious(self) -> bool:
        return bool(self.reasons)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    if is_windows():
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def log(msg: str, log_path: Path) -> None:
    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {msg}"
    print(line)
    try:
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def run_cmd(args: Sequence[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def load_ip_list(path: Path) -> Set[str]:
    items: Set[str] = set()
    if not path.exists():
        return items
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # allow comments after IP
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            # Accept single IP or CIDR; store canonical string
            net = ipaddress.ip_network(line, strict=False)
            items.add(str(net))
        except ValueError:
            continue
    return items


def load_device_names(path: Path = DEFAULT_DEVICES) -> Dict[str, str]:
    """Map IP -> friendly name from devices.txt."""
    names: Dict[str, str] = {}
    if not path.exists():
        return names
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        parts = re.split(r"[\s,=]+", line, maxsplit=1)
        if len(parts) < 2:
            continue
        ip, name = parts[0].strip(), parts[1].strip()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue
        if name:
            names[ip] = name
    return names


def save_device_name(ip: str, name: str, path: Path = DEFAULT_DEVICES) -> None:
    if not ip or not name:
        return
    names = load_device_names(path)
    names[ip] = name
    lines = [
        "# Friendly names for LAN devices (IP then name).",
        "# Used in inventory, triage, and allowlist memory.",
    ]
    for key in sorted(names, key=lambda x: tuple(int(p) for p in x.split("."))):
        lines.append(f"{key}  {names[key]}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_allow_state(path: Path = DEFAULT_ALLOW_STATE) -> Dict[str, dict]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_allow_state(state: Dict[str, dict], path: Path = DEFAULT_ALLOW_STATE) -> None:
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def suspicious_ports_from_open(open_ports: Sequence[int]) -> List[int]:
    flagged = []
    for p in open_ports:
        if p in SUSPICIOUS_LISTEN_PORTS or p in (23, 2323, 7547, 5555, 49152):
            flagged.append(int(p))
    return sorted(set(flagged))


def fingerprint_from_finding(finding: Connection, lan_hosts: Optional[List[LanHost]] = None) -> dict:
    open_ports: List[int] = []
    name = ""
    if lan_hosts:
        host = next((h for h in lan_hosts if h.ip == finding.remote_ip), None)
        if host:
            open_ports = list(host.open_ports)
            name = host.hostname or ""
    if finding.remote_port:
        open_ports = sorted(set(open_ports + [int(finding.remote_port)]))
    return {
        "name": name or finding.process_name or "",
        "allowed_at": dt.datetime.now().isoformat(timespec="seconds"),
        "ports": sorted(set(int(p) for p in open_ports if p)),
        "suspicious_ports": suspicious_ports_from_open(open_ports),
        "reasons": list(finding.reasons),
        "remote_port": int(finding.remote_port or 0),
        "process_name": finding.process_name or "",
        "proto": finding.proto,
    }


def traffic_worsened(previous: dict, current: dict) -> Tuple[bool, List[str]]:
    """
    True if current activity is worse than what was allowlisted.
    Re-prompt only on negative change.
    """
    changes: List[str] = []
    prev_ports = set(int(p) for p in (previous.get("suspicious_ports") or []))
    curr_ports = set(int(p) for p in (current.get("suspicious_ports") or []))
    new_ports = sorted(curr_ports - prev_ports)
    if new_ports:
        changes.append("new suspicious port(s): " + ",".join(str(p) for p in new_ports))

    prev_reasons = set(previous.get("reasons") or [])
    curr_reasons = set(current.get("reasons") or [])
    # Ignore identical reason text churn; focus on new reason categories with new ports already covered
    new_reason_texts = sorted(r for r in (curr_reasons - prev_reasons) if "new suspicious" not in r)
    # If reasons mention ports we already accepted, don't count as worse
    for r in list(new_reason_texts):
        ports_in_reason = {int(x) for x in re.findall(r"\b(\d{2,5})\b", r)}
        if ports_in_reason and ports_in_reason.issubset(prev_ports):
            new_reason_texts.remove(r)
    if new_reason_texts:
        changes.append("new threat reason(s): " + "; ".join(new_reason_texts))

    prev_proc = (previous.get("process_name") or "").lower()
    curr_proc = (current.get("process_name") or "").lower()
    if curr_proc and curr_proc != prev_proc and curr_proc in SUSPICIOUS_PROCESS_NAMES:
        if Path(curr_proc).stem.lower() in SUSPICIOUS_PROCESS_NAMES:
            changes.append(f"suspicious process appeared: {curr_proc}")

    prev_rport = int(previous.get("remote_port") or 0)
    curr_rport = int(current.get("remote_port") or 0)
    if (
        curr_rport
        and curr_rport in SUSPICIOUS_REMOTE_PORTS
        and curr_rport != prev_rport
        and curr_rport not in prev_ports
    ):
        changes.append(f"new suspicious remote port: {curr_rport}")

    return (bool(changes), changes)


def allowlist_should_skip(
    ip: str,
    allowlist: Set[str],
    state: Dict[str, dict],
    current_fp: dict,
    state_path: Path = DEFAULT_ALLOW_STATE,
) -> Tuple[bool, str]:
    """
    Returns (skip?, note).
    If IP is allowlisted and traffic is not worse, skip prompting.
    If allowlisted with no fingerprint yet, seed baseline and skip.
    If traffic worsened, do NOT skip (ask again).
    """
    if not ip_in_list(ip, allowlist):
        return False, ""

    prev = state.get(ip)
    if not prev:
        # First time seeing this allowlisted IP after upgrade: remember baseline, don't ask
        state[ip] = dict(current_fp)
        state[ip]["allowed_at"] = state[ip].get("allowed_at") or dt.datetime.now().isoformat(
            timespec="seconds"
        )
        state[ip]["note"] = "baseline seeded from allowlist"
        save_allow_state(state, state_path)
        return True, "allowlisted (baseline saved; will only re-ask if traffic worsens)"

    worsened, changes = traffic_worsened(prev, current_fp)
    if worsened:
        return False, "allowlisted but traffic worsened: " + "; ".join(changes)

    return True, "allowlisted (unchanged; not asking again)"


def ip_in_list(ip: str, networks: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in networks:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_local_or_skip(ip: str) -> bool:
    if not ip or ip in ("-", "*"):
        return True
    for prefix in PRIVATE_SKIP_PREFIXES:
        if ip.startswith(prefix) or ip == prefix.rstrip("."):
            return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_loopback
        or addr.is_unspecified
        or addr.is_link_local
        or addr.is_multicast
    )


def is_private_lan(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def normalize_ip(ip: str) -> str:
    # Strip IPv6 brackets and zone ids: [::1%eth0] / fe80::1%12
    ip = ip.strip("[]")
    if "%" in ip:
        ip = ip.split("%", 1)[0]
    # Windows sometimes returns IPv4-mapped ::ffff:x.x.x.x
    if ip.lower().startswith("::ffff:"):
        ip = ip[7:]
    return ip


def parse_endpoint(endpoint: str) -> Tuple[str, int]:
    endpoint = endpoint.strip()
    if endpoint in ("*", "-", ""):
        return "0.0.0.0", 0
    # [ipv6]:port
    if endpoint.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", endpoint)
        if m:
            return normalize_ip(m.group(1)), int(m.group(2))
    # ipv4:port or host:port (last colon)
    if endpoint.count(":") == 1:
        host, port = endpoint.rsplit(":", 1)
        return normalize_ip(host), int(port) if port.isdigit() else 0
    # bare ipv6 without port (ss sometimes)
    if ":" in endpoint and not endpoint.rsplit(":", 1)[-1].isdigit():
        return normalize_ip(endpoint), 0
    # ipv6:port without brackets — last numeric segment is port
    m = re.match(r"^(.+):(\d+)$", endpoint)
    if m:
        return normalize_ip(m.group(1)), int(m.group(2))
    return normalize_ip(endpoint), 0


# ---------------------------------------------------------------------------
# Process name resolution
# ---------------------------------------------------------------------------

def process_name_for_pid(pid: Optional[int]) -> str:
    if not pid or pid <= 0:
        return ""
    if is_windows():
        code, out, _ = run_cmd(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]
        )
        if code == 0 and out.strip():
            try:
                row = next(csv.reader([out.strip().splitlines()[0]]))
                if row:
                    return row[0].strip('"')
            except Exception:
                pass
        return ""
    # Linux: /proc/<pid>/comm
    comm = Path(f"/proc/{pid}/comm")
    if comm.exists():
        try:
            return comm.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            pass
    code, out, _ = run_cmd(["ps", "-p", str(pid), "-o", "comm="])
    return out.strip() if code == 0 else ""


# ---------------------------------------------------------------------------
# Connection enumeration
# ---------------------------------------------------------------------------

def enumerate_connections_windows() -> List[Connection]:
    conns: List[Connection] = []
    # Prefer PowerShell for PID; fall back to netstat
    ps = (
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State | "
        "ConvertTo-Json -Compress"
    )
    code, out, _ = run_cmd(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        timeout=60,
    )
    if code == 0 and out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                state = str(item.get("State", "")).upper()
                # PowerShell uses numeric or string states depending on version
                state_map = {
                    "1": "CLOSED", "2": "LISTEN", "3": "SYN_SENT",
                    "4": "SYN_RECEIVED", "5": "ESTABLISHED", "6": "FIN_WAIT_1",
                    "7": "FIN_WAIT_2", "8": "CLOSE_WAIT", "9": "CLOSING",
                    "10": "LAST_ACK", "11": "TIME_WAIT", "12": "DELETE_TCB",
                    "Listen": "LISTEN", "Established": "ESTABLISHED",
                    "Bound": "BOUND", "TimeWait": "TIME_WAIT",
                    "CloseWait": "CLOSE_WAIT", "SynSent": "SYN_SENT",
                }
                state = state_map.get(str(item.get("State")), state)
                pid = item.get("OwningProcess")
                try:
                    pid_i = int(pid) if pid is not None else None
                except (TypeError, ValueError):
                    pid_i = None
                remote = normalize_ip(str(item.get("RemoteAddress") or "0.0.0.0"))
                local = normalize_ip(str(item.get("LocalAddress") or "0.0.0.0"))
                conns.append(
                    Connection(
                        proto="tcp",
                        local_ip=local,
                        local_port=int(item.get("LocalPort") or 0),
                        remote_ip=remote,
                        remote_port=int(item.get("RemotePort") or 0),
                        state=state,
                        pid=pid_i,
                    )
                )
            return conns
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    # Fallback: netstat -ano
    code, out, _ = run_cmd(["netstat", "-ano"])
    if code != 0:
        return conns
    for line in out.splitlines():
        line = line.strip()
        if not line.lower().startswith(("tcp", "udp")):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        local_ip, local_port = parse_endpoint(parts[1])
        if proto.startswith("udp"):
            remote_ip, remote_port = parse_endpoint(parts[2] if len(parts) > 2 else "*:*")
            state = "UDP"
            pid_s = parts[3] if len(parts) > 3 else "0"
        else:
            if len(parts) < 5:
                continue
            remote_ip, remote_port = parse_endpoint(parts[2])
            state = parts[3].upper()
            pid_s = parts[4]
        try:
            pid_i = int(pid_s)
        except ValueError:
            pid_i = None
        conns.append(
            Connection(
                proto=proto[:3],
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                pid=pid_i,
            )
        )
    return conns


def enumerate_connections_linux() -> List[Connection]:
    conns: List[Connection] = []
    # Prefer ss
    if shutil.which("ss"):
        code, out, _ = run_cmd(["ss", "-H", "-tunap"])
        if code == 0:
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = re.split(r"\s+", line)
                if len(parts) < 5:
                    continue
                proto = parts[0].lower()
                state = parts[1].upper() if not proto.startswith("udp") else "UDP"
                # ss columns vary: Netid State Recv-Q Send-Q Local Peer Process
                # With -H -tunap typically: proto state rq sq local peer users(...)
                if len(parts) >= 6 and parts[1].isdigit():
                    # older/no-state layout for udp: Netid Recv-Q Send-Q Local Peer
                    local_ep, peer_ep = parts[3], parts[4]
                    state = "UDP" if proto.startswith("udp") else state
                    rest = " ".join(parts[5:])
                else:
                    local_ep, peer_ep = parts[4], parts[5]
                    rest = " ".join(parts[6:]) if len(parts) > 6 else ""
                local_ip, local_port = parse_endpoint(local_ep)
                remote_ip, remote_port = parse_endpoint(peer_ep)
                pid_i = None
                pname = ""
                m = re.search(r'pid=(\d+)', rest)
                if m:
                    pid_i = int(m.group(1))
                m2 = re.search(r'"([^"]+)"', rest)
                if m2:
                    pname = m2.group(1)
                conns.append(
                    Connection(
                        proto=proto[:3],
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        state=state,
                        pid=pid_i,
                        process_name=pname,
                    )
                )
            return conns

    # Fallback netstat
    code, out, _ = run_cmd(["netstat", "-tunap"])
    if code != 0:
        return conns
    for line in out.splitlines():
        line = line.strip()
        if not line.lower().startswith(("tcp", "udp")):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        local_ip, local_port = parse_endpoint(parts[3])
        remote_ip, remote_port = parse_endpoint(parts[4])
        state = parts[5].upper() if proto.startswith("tcp") else "UDP"
        pid_i = None
        pname = ""
        prog = parts[-1] if len(parts) >= 7 else ""
        m = re.match(r"(\d+)/(.*)", prog)
        if m:
            pid_i = int(m.group(1))
            pname = m.group(2)
        conns.append(
            Connection(
                proto=proto[:3],
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                pid=pid_i,
                process_name=pname,
            )
        )
    return conns


def enumerate_connections() -> List[Connection]:
    if is_windows():
        return enumerate_connections_windows()
    return enumerate_connections_linux()


# ---------------------------------------------------------------------------
# Scoring / detection
# ---------------------------------------------------------------------------

def score_connection(
    conn: Connection,
    allowlist: Set[str],
    blocklist: Set[str],
) -> List[str]:
    reasons: List[str] = []
    remote = conn.remote_ip

    if is_local_or_skip(remote) and conn.state not in ("LISTEN", "LISTENING"):
        return reasons

    # Allowlist is handled later via fingerprint (re-ask only if traffic worsens)

    if remote and not is_local_or_skip(remote) and ip_in_list(remote, blocklist):
        reasons.append(f"remote IP on blocklist ({remote})")

    state = conn.state.upper()
    listening = state in ("LISTEN", "LISTENING")

    if listening and conn.local_port in SUSPICIOUS_LISTEN_PORTS:
        reasons.append(f"suspicious listening port {conn.local_port}")

    if state in ("ESTABLISHED", "SYN_SENT", "SYN_RECEIVED") or state == "UDP":
        if conn.remote_port in SUSPICIOUS_REMOTE_PORTS:
            reasons.append(f"suspicious remote port {conn.remote_port}")
        if conn.local_port in SUSPICIOUS_REMOTE_PORTS and not is_local_or_skip(remote):
            reasons.append(f"suspicious local port {conn.local_port} with remote peer")

    pname = (conn.process_name or "").lower()
    base = Path(pname).stem.lower() if pname else ""
    # Exact executable stem only — substring matches false-positive too often
    # (e.g. "nc" inside "...Sync.exe").
    if base in SUSPICIOUS_PROCESS_NAMES:
        reasons.append(f"suspicious process name '{conn.process_name}'")

    return reasons


def enrich_and_detect(
    connections: List[Connection],
    allowlist: Set[str],
    blocklist: Set[str],
    allow_state: Optional[Dict[str, dict]] = None,
    state_path: Path = DEFAULT_ALLOW_STATE,
) -> List[Connection]:
    findings: List[Connection] = []
    seen: Set[str] = set()
    state = allow_state if allow_state is not None else load_allow_state(state_path)
    device_names = load_device_names()
    for conn in connections:
        if not conn.process_name and conn.pid:
            conn.process_name = process_name_for_pid(conn.pid)
        # Prefer friendly LAN device name when talking to a known IP
        if conn.remote_ip in device_names and not conn.process_name:
            conn.process_name = device_names[conn.remote_ip]
        reasons = score_connection(conn, allowlist, blocklist)
        if not reasons:
            continue

        if conn.remote_ip and not is_local_or_skip(conn.remote_ip):
            fp = fingerprint_from_finding(conn, None)
            if conn.remote_ip in device_names:
                fp["name"] = device_names[conn.remote_ip]
            skip, note = allowlist_should_skip(
                conn.remote_ip, allowlist, state, fp, state_path
            )
            if skip:
                continue
            if note.startswith("allowlisted but traffic worsened"):
                reasons = [note] + reasons

        conn.reasons = reasons
        if conn.key in seen:
            continue
        seen.add(conn.key)
        findings.append(conn)
    return findings


# ---------------------------------------------------------------------------
# Remediation: firewall + process kill
# ---------------------------------------------------------------------------

def block_ip_windows(ip: str, dry_run: bool, log_path: Path) -> bool:
    rule_name = f"{RULE_PREFIX}-Block-{ip.replace(':', '-')}"
    # inbound + outbound block
    cmds = [
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}-In", "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes",
        ],
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}-Out", "dir=out", "action=block",
            f"remoteip={ip}", "enable=yes",
        ],
    ]
    ok = True
    for cmd in cmds:
        if dry_run:
            log(f"DRY-RUN would run: {' '.join(cmd)}", log_path)
            continue
        code, _, err = run_cmd(cmd)
        if code != 0:
            log(f"Firewall rule failed for {ip}: {err.strip()}", log_path)
            ok = False
        else:
            direction = "in" if "dir=in" in cmd else "out"
            log(f"Blocked {ip} via Windows Firewall ({direction})", log_path)
    return ok


def block_ip_linux(ip: str, dry_run: bool, log_path: Path) -> bool:
    # Prefer nft, then iptables, then ufw
    if shutil.which("nft"):
        cmds = [
            ["nft", "insert", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop", "comment", f"{RULE_PREFIX}"],
            ["nft", "insert", "rule", "inet", "filter", "output", "ip", "daddr", ip, "drop", "comment", f"{RULE_PREFIX}"],
        ]
        # IPv6 variants
        try:
            if ipaddress.ip_address(ip).version == 6:
                cmds = [
                    ["nft", "insert", "rule", "inet", "filter", "input", "ip6", "saddr", ip, "drop", "comment", f"{RULE_PREFIX}"],
                    ["nft", "insert", "rule", "inet", "filter", "output", "ip6", "daddr", ip, "drop", "comment", f"{RULE_PREFIX}"],
                ]
        except ValueError:
            pass
    elif shutil.which("iptables"):
        cmds = [
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", RULE_PREFIX],
            ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP", "-m", "comment", "--comment", RULE_PREFIX],
        ]
        try:
            if ipaddress.ip_address(ip).version == 6 and shutil.which("ip6tables"):
                cmds = [
                    ["ip6tables", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", RULE_PREFIX],
                    ["ip6tables", "-I", "OUTPUT", "-d", ip, "-j", "DROP", "-m", "comment", "--comment", RULE_PREFIX],
                ]
        except ValueError:
            pass
    elif shutil.which("ufw"):
        cmds = [["ufw", "deny", "from", ip], ["ufw", "deny", "to", ip]]
    else:
        log("No firewall tool found (nft/iptables/ufw). Cannot block.", log_path)
        return False

    ok = True
    for cmd in cmds:
        if dry_run:
            log(f"DRY-RUN would run: {' '.join(cmd)}", log_path)
            continue
        code, _, err = run_cmd(cmd)
        if code != 0:
            # nft table may not exist on minimal systems — try iptables fallback once
            log(f"Firewall command failed ({' '.join(cmd)}): {err.strip()}", log_path)
            ok = False
        else:
            log(f"Blocked {ip} via {' '.join(cmd[:2])}", log_path)
    return ok


def block_ip(
    ip: str,
    dry_run: bool,
    log_path: Path,
    *,
    allow_private: bool = False,
    protected: Optional[Set[str]] = None,
) -> bool:
    protected = protected or set()
    if ip in protected or is_local_or_skip(ip):
        log(f"Refusing to block protected/local address {ip}", log_path)
        return False
    if is_private_lan(ip) and not allow_private:
        log(f"Refusing to block private LAN address {ip} (use --lan to allow)", log_path)
        return False
    if is_windows():
        return block_ip_windows(ip, dry_run, log_path)
    return block_ip_linux(ip, dry_run, log_path)


def kill_process(pid: Optional[int], dry_run: bool, log_path: Path) -> bool:
    if not pid or pid <= 0:
        return False
    # Never kill PID 0/4 (Windows System) or 1 (Linux init)
    if pid in (0, 1, 4):
        log(f"Refusing to kill protected PID {pid}", log_path)
        return False
    if dry_run:
        log(f"DRY-RUN would terminate PID {pid}", log_path)
        return True
    if is_windows():
        code, _, err = run_cmd(["taskkill", "/PID", str(pid), "/F"])
    else:
        code, _, err = run_cmd(["kill", "-9", str(pid)])
    if code == 0:
        log(f"Terminated PID {pid}", log_path)
        return True
    log(f"Failed to terminate PID {pid}: {err.strip()}", log_path)
    return False


def append_blocklist(ip: str, path: Path) -> None:
    existing = load_ip_list(path)
    if ip_in_list(ip, existing):
        return
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"{ip}  # added {dt.datetime.now().isoformat(timespec='seconds')}\n")


def append_allowlist(
    ip: str,
    path: Path,
    *,
    finding: Optional[Connection] = None,
    lan_hosts: Optional[List[LanHost]] = None,
    device_name: str = "",
    state_path: Path = DEFAULT_ALLOW_STATE,
) -> None:
    existing = load_ip_list(path)
    if not ip_in_list(ip, existing):
        with path.open("a", encoding="utf-8") as fh:
            label = device_name or (finding.process_name if finding else "") or ""
            extra = f" name={label}" if label else ""
            fh.write(
                f"{ip}  # allowed {dt.datetime.now().isoformat(timespec='seconds')}{extra}\n"
            )

    fp = (
        fingerprint_from_finding(finding, lan_hosts)
        if finding
        else {
            "name": device_name,
            "allowed_at": dt.datetime.now().isoformat(timespec="seconds"),
            "ports": [],
            "suspicious_ports": [],
            "reasons": [],
            "remote_port": 0,
            "process_name": "",
            "proto": "",
        }
    )
    if device_name:
        fp["name"] = device_name
    state = load_allow_state(state_path)
    state[ip] = fp
    save_allow_state(state, state_path)
    if device_name:
        save_device_name(ip, device_name)


def reverse_dns(ip: str) -> str:
    if not ip or is_local_or_skip(ip):
        return ""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except OSError:
        return ""


def process_details(pid: Optional[int]) -> Dict[str, str]:
    """Return path, command line, user, parent, window title for a PID."""
    info = {
        "pid": str(pid or ""),
        "name": "",
        "path": "",
        "cmdline": "",
        "user": "",
        "parent_pid": "",
        "parent_name": "",
        "window_title": "",
    }
    if not pid or pid <= 0:
        return info
    info["name"] = process_name_for_pid(pid)

    if is_windows():
        ps = (
            f"$p = Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\" "
            f"-ErrorAction SilentlyContinue; "
            f"if (-not $p) {{ '{{}}'; return }}; "
            f"$owner = $null; try {{ $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner "
            f"-ErrorAction SilentlyContinue; "
            f"if ($o) {{ $owner = ($o.Domain + '\\\\' + $o.User) }} }} catch {{}}; "
            f"$title = ''; try {{ $title = (Get-Process -Id {pid} -ErrorAction SilentlyContinue)"
            f".MainWindowTitle }} catch {{}}; "
            f"$obj = [ordered]@{{ "
            f"Name=$p.Name; Path=$p.ExecutablePath; CommandLine=$p.CommandLine; "
            f"ParentProcessId=$p.ParentProcessId; User=$owner; WindowTitle=$title "
            f"}}; $obj | ConvertTo-Json -Compress"
        )
        code, out, _ = run_cmd(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            timeout=20,
        )
        if code == 0 and out.strip():
            try:
                data = json.loads(out)
                info["name"] = str(data.get("Name") or info["name"] or "")
                info["path"] = str(data.get("Path") or "")
                info["cmdline"] = str(data.get("CommandLine") or "")
                info["user"] = str(data.get("User") or "")
                ppid = data.get("ParentProcessId")
                if ppid:
                    info["parent_pid"] = str(ppid)
                    info["parent_name"] = process_name_for_pid(int(ppid))
                info["window_title"] = str(data.get("WindowTitle") or "")
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        return info

    # Linux /proc
    try:
        info["cmdline"] = (
            Path(f"/proc/{pid}/cmdline")
            .read_bytes()
            .replace(b"\x00", b" ")
            .decode("utf-8", "ignore")
            .strip()
        )
    except OSError:
        pass
    try:
        exe = Path(f"/proc/{pid}/exe").resolve()
        info["path"] = str(exe)
    except OSError:
        pass
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="ignore")
        for line in status.splitlines():
            if line.startswith("PPid:"):
                info["parent_pid"] = line.split(":", 1)[1].strip()
                if info["parent_pid"].isdigit():
                    info["parent_name"] = process_name_for_pid(int(info["parent_pid"]))
            elif line.startswith("Name:"):
                info["name"] = info["name"] or line.split(":", 1)[1].strip()
    except OSError:
        pass
    try:
        # UID from status -> approximate user
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("Uid:"):
                uid = line.split()[1]
                code, out, _ = run_cmd(["getent", "passwd", uid])
                if code == 0 and out:
                    info["user"] = out.split(":", 1)[0]
                break
    except OSError:
        pass
    return info


def connections_for_pid(pid: Optional[int], all_conns: Optional[List[Connection]] = None) -> List[Connection]:
    if not pid:
        return []
    conns = all_conns if all_conns is not None else enumerate_connections()
    return [c for c in conns if c.pid == pid]


def connections_to_ip(ip: str, all_conns: Optional[List[Connection]] = None) -> List[Connection]:
    if not ip:
        return []
    conns = all_conns if all_conns is not None else enumerate_connections()
    return [c for c in conns if c.remote_ip == ip or c.local_ip == ip]


def format_conn_line(c: Connection) -> str:
    return (
        f"    {c.proto}  {c.local_ip}:{c.local_port}  ->  "
        f"{c.remote_ip}:{c.remote_port}  [{c.state}]"
    )


def show_threat_view(
    finding: Connection,
    lan_hosts: List[LanHost],
    log_path: Path,
) -> None:
    """Show what the suspicious actor appears to be doing / connected to."""
    print()
    print("=" * 64)
    print("  THREAT VIEW - what this activity looks like right now")
    print("=" * 64)
    print(f"  Reason : {'; '.join(finding.reasons)}")
    print(
        f"  Link   : {finding.proto} {finding.local_ip}:{finding.local_port} -> "
        f"{finding.remote_ip}:{finding.remote_port}  ({finding.state})"
    )

    remote_name = reverse_dns(finding.remote_ip)
    if remote_name:
        print(f"  Remote DNS : {remote_name}")

    if finding.proto == "lan":
        host = next((h for h in lan_hosts if h.ip == finding.remote_ip), None)
        friendly = (
            load_device_names().get(finding.remote_ip)
            or (host.hostname if host else "")
            or finding.process_name
            or "-"
        )
        print(f"  Device     : {friendly}")
        print(f"  LAN IP     : {finding.remote_ip}")
        if host:
            if host.hostname and host.hostname != friendly:
                print(f"  Hostname   : {host.hostname}")
            print(f"  MAC        : {host.mac or '-'}")
            print(
                f"  Open ports : "
                + (",".join(str(p) for p in host.open_ports) if host.open_ports else "-")
            )
            if host.is_gateway:
                print("  Note       : this is your default gateway (protected from block)")
        related = connections_to_ip(finding.remote_ip)
        print(f"  Your PC's sessions with this device ({len(related)}):")
        if related:
            for c in related[:30]:
                print(format_conn_line(c))
            if len(related) > 30:
                print(f"    ... +{len(related) - 30} more")
        else:
            print("    (none right now - device is reachable/open but idle toward you)")
        print(
            "  Note: press [U] to view this device's screen "
            "(needs Network Guard Agent on that device, or RDP)."
        )
        print("=" * 64)
        return

    # Local process threat
    details = process_details(finding.pid)
    print(f"  Process    : {details.get('name') or finding.process_name or '-'}")
    print(f"  PID        : {details.get('pid') or '-'}")
    print(f"  User       : {details.get('user') or '-'}")
    print(f"  Path       : {details.get('path') or '-'}")
    print(f"  Command    : {details.get('cmdline') or '-'}")
    print(
        f"  Parent     : {details.get('parent_name') or '-'} "
        f"(PID {details.get('parent_pid') or '-'})"
    )
    title = (details.get("window_title") or "").strip()
    print(f"  Window title (what is on screen): {title if title else '(no visible window / background)'}")

    related = connections_for_pid(finding.pid)
    print(f"  All network links for this process ({len(related)}):")
    if related:
        for c in related[:40]:
            extra = reverse_dns(c.remote_ip)
            suffix = f"  dns={extra}" if extra else ""
            print(format_conn_line(c) + suffix)
        if len(related) > 40:
            print(f"    ... +{len(related) - 40} more")
    else:
        print("    (no active sockets found for this PID)")
    print("=" * 64)
    log(
        f"VIEW pid={finding.pid} name={details.get('name')} remote={finding.remote_ip} "
        f"title={title!r} cmdline={details.get('cmdline')!r}",
        log_path,
    )


def watch_live_activity(finding: Connection, seconds: int, log_path: Path) -> None:
    """Resample connections so you can see what it connects to live."""
    seconds = max(3, min(seconds, 60))
    print()
    print(f"  Watching live activity for {seconds}s (Ctrl+C to stop early)...")
    print("  New/changed remote endpoints will be listed below:")
    seen: Set[str] = set()
    try:
        end = time.time() + seconds
        while time.time() < end:
            if finding.proto == "lan":
                snap = connections_to_ip(finding.remote_ip)
            else:
                snap = connections_for_pid(finding.pid)
            for c in snap:
                key = f"{c.remote_ip}:{c.remote_port}/{c.state}"
                if key not in seen and not is_local_or_skip(c.remote_ip):
                    seen.add(key)
                    dns = reverse_dns(c.remote_ip)
                    dns_s = f" ({dns})" if dns else ""
                    line = (
                        f"    + {c.remote_ip}:{c.remote_port}{dns_s}  "
                        f"via local {c.local_port}  [{c.state}]"
                    )
                    print(line)
                    log(f"LIVE {line.strip()}", log_path)
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("  (watch interrupted)")
    if not seen:
        print("  No new external endpoints observed in that window.")
    print()


def prompt_choice(prompt: str) -> str:
    try:
        return input(prompt).strip().lower()
    except EOFError:
        return "s"


# ---------------------------------------------------------------------------
# UI viewing — local process windows, remote agent stream, or RDP
# ---------------------------------------------------------------------------

AGENT_PORT = 38765
AGENT_TOKEN_FILE = SCRIPT_DIR / "agent_token.txt"
UI_CAPTURE_DIR = SCRIPT_DIR / "ui_captures"


def load_agent_token() -> str:
    if AGENT_TOKEN_FILE.exists():
        return AGENT_TOKEN_FILE.read_text(encoding="utf-8").strip()
    return ""


def windows_for_pid(pid: int) -> List[Tuple[int, str]]:
    """Return [(hwnd, title), ...] visible top-level windows owned by pid."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    results: List[Tuple[int, str]] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def enum_proc(hwnd, _lparam):  # noqa: N803
        if not user32.IsWindowVisible(hwnd):
            return True
        pid_out = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_out))
        if int(pid_out.value) != int(pid):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value.strip()
        # Include untitled tool windows that still have size
        rect = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        w = rect.right - rect.left
        h = rect.bottom - rect.top
        if w < 50 or h < 50:
            return True
        results.append((int(hwnd), title or "(untitled window)"))
        return True

    user32.EnumWindows(enum_proc, 0)
    return results


def capture_hwnd_image(hwnd: int):
    """Capture a window's pixels into a PIL Image."""
    import ctypes
    from ctypes import wintypes

    from PIL import Image

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    # DPI awareness helps on modern Windows
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass

    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    width = max(1, rect.right - rect.left)
    height = max(1, rect.bottom - rect.top)

    hwnd_dc = user32.GetWindowDC(hwnd)
    if not hwnd_dc:
        raise RuntimeError("GetWindowDC failed")
    mem_dc = gdi32.CreateCompatibleDC(hwnd_dc)
    bmp = gdi32.CreateCompatibleBitmap(hwnd_dc, width, height)
    old = gdi32.SelectObject(mem_dc, bmp)

    # PW_RENDERFULLCONTENT = 2 (Win8.1+)
    PW_RENDERFULLCONTENT = 2
    ok = user32.PrintWindow(hwnd, mem_dc, PW_RENDERFULLCONTENT)
    if not ok:
        ok = user32.PrintWindow(hwnd, mem_dc, 0)
    if not ok:
        # Fallback BitBlt from screen
        gdi32.BitBlt(
            mem_dc, 0, 0, width, height, hwnd_dc, 0, 0, 0x00CC0020
        )  # SRCCOPY

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", wintypes.LONG),
            ("biHeight", wintypes.LONG),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", wintypes.LONG),
            ("biYPelsPerMeter", wintypes.LONG),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    bmi = BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.biWidth = width
    bmi.biHeight = -height  # top-down
    bmi.biPlanes = 1
    bmi.biBitCount = 32
    bmi.biCompression = 0

    buf_len = width * height * 4
    buf = (ctypes.c_ubyte * buf_len)()
    gdi32.GetDIBits(mem_dc, bmp, 0, height, buf, ctypes.byref(bmi), 0)

    gdi32.SelectObject(mem_dc, old)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem_dc)
    user32.ReleaseDC(hwnd, hwnd_dc)

    img = Image.frombuffer("RGB", (width, height), bytes(buf), "raw", "BGRX", 0, 1)
    return img.copy()


def capture_desktop_image():
    from PIL import ImageGrab

    return ImageGrab.grab(all_screens=True)


def capture_local_ui(pid: Optional[int]):
    """
    Return (image, label). Prefers the process's own window(s);
    falls back to full desktop with a note.
    """
    if is_windows() and pid:
        wins = windows_for_pid(pid)
        # Prefer window with a title (likely the UI the user cares about)
        wins_sorted = sorted(wins, key=lambda x: (0 if x[1] != "(untitled window)" else 1, -len(x[1])))
        for hwnd, title in wins_sorted:
            try:
                img = capture_hwnd_image(hwnd)
                return img, f"window: {title} (hwnd={hwnd})"
            except Exception:
                continue
        # Try desktop as last resort for background processes
        img = capture_desktop_image()
        return img, "full desktop (process has no visible window)"
    img = capture_desktop_image()
    return img, "full desktop"


def save_ui_capture(img, prefix: str) -> Path:
    UI_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = UI_CAPTURE_DIR / f"{prefix}_{stamp}.jpg"
    img.convert("RGB").save(path, format="JPEG", quality=70)
    return path


def fetch_agent_screenshot(ip: str, token: str, port: int = AGENT_PORT, timeout: float = 4.0):
    """Return PIL Image from remote Network Guard agent, or raise."""
    import urllib.error
    import urllib.request
    from PIL import Image

    url = f"http://{ip}:{port}/screenshot?token={token}"
    req = urllib.request.Request(url, headers={"User-Agent": "NetworkGuard/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    return Image.open(io.BytesIO(data)).convert("RGB")


def agent_reachable(ip: str, token: str, port: int = AGENT_PORT) -> bool:
    import urllib.error
    import urllib.request

    url = f"http://{ip}:{port}/health"
    try:
        with urllib.request.urlopen(url, timeout=1.5) as resp:
            if resp.status != 200:
                return False
        # token check via info
        info_url = f"http://{ip}:{port}/info?token={token}"
        with urllib.request.urlopen(info_url, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def open_rdp(ip: str, log_path: Path) -> Optional[subprocess.Popen]:
    """Launch mstsc to ip; returns the process handle when possible."""
    if not is_windows():
        log("RDP launch is only automated on Windows (use Remmina/xfreerdp).", log_path)
        return None
    UI_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    rdp_file = UI_CAPTURE_DIR / f"threat_{ip.replace('.', '_')}.rdp"
    rdp_file.write_text(
        "\n".join(
            [
                f"full address:s:{ip}",
                "prompt for credentials:i:1",
                "screen mode id:i:1",
                "desktopwidth:i:1280",
                "desktopheight:i:720",
                "session bpp:i:32",
                "authentication level:i:2",
                "negotiate security layer:i:1",
                "enablecredsspsupport:i:1",
                f"username:s:{os.environ.get('USERNAME', '')}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    log(f"Launching Remote Desktop session to {ip} ...", log_path)
    try:
        return subprocess.Popen(["mstsc", str(rdp_file)], shell=False)
    except OSError as exc:
        log(f"Failed to launch mstsc: {exc}", log_path)
        try:
            return subprocess.Popen(["mstsc", f"/v:{ip}"], shell=False)
        except OSError as exc2:
            log(f"Failed to launch mstsc /v: {exc2}", log_path)
            return None


def find_rdp_session_windows(ip: str = "") -> List[Tuple[int, str, int]]:
    """
    Find Remote Desktop Connection windows.
    Returns list of (hwnd, title, pid).
    """
    if not is_windows():
        return []
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    results: List[Tuple[int, str, int]] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def enum_proc(hwnd, _lparam):  # noqa: N803
        if not user32.IsWindowVisible(hwnd):
            return True
        pid_out = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_out))
        pid = int(pid_out.value)
        name = (process_name_for_pid(pid) or "").lower()
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value.strip()
        title_l = title.lower()
        is_rdp = (
            name.startswith("mstsc")
            or "remote desktop" in title_l
            or title_l.endswith("rdc")
        )
        if not is_rdp:
            return True
        if ip and ip not in title and ip not in title.replace("_", "."):
            # Still accept generic RDP windows when only one session is open
            pass
        rect = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        if (rect.right - rect.left) < 200 or (rect.bottom - rect.top) < 150:
            return True
        results.append((int(hwnd), title or "Remote Desktop Connection", pid))
        return True

    user32.EnumWindows(enum_proc, 0)
    if ip:
        exact = [r for r in results if ip in r[1]]
        if exact:
            return exact
    return results


def wait_for_rdp_window(ip: str, timeout_sec: float = 45.0) -> Optional[Tuple[int, str, int]]:
    print(f"  Waiting for RDP window to {ip} (sign in if Windows asks)...")
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        wins = find_rdp_session_windows(ip)
        if wins:
            # Prefer title containing the IP
            wins_sorted = sorted(wins, key=lambda w: (0 if ip in w[1] else 1, -len(w[1])))
            return wins_sorted[0]
        time.sleep(0.6)
    return None


def capture_rdp_session_frame(ip: str):
    """Capture the live RDP session window (what the remote desktop is showing)."""
    wins = find_rdp_session_windows(ip)
    if not wins:
        # Fall back to any RDP window
        wins = find_rdp_session_windows("")
    if wins:
        hwnd, title, _pid = sorted(wins, key=lambda w: (0 if ip in w[1] else 1, -len(w[1])))[0]
        try:
            img = capture_hwnd_image(hwnd)
            return img, f"RDP session window: {title}"
        except Exception as exc:
            return capture_desktop_image(), f"RDP capture fallback desktop ({exc})"
    return capture_desktop_image(), "Waiting for RDP session window..."


def start_rdp_browser_session(
    ip: str,
    friendly: str,
    log_path: Path,
) -> None:
    """
    Open an RDP connection to the threat device, then mirror that session
    live into the default web browser so you can watch movements.
    """
    proc = open_rdp(ip, log_path)
    if proc is None and not is_windows():
        print("  Cannot start RDP browser session on this OS automatically.")
        return

    win = wait_for_rdp_window(ip, timeout_sec=60.0)
    if not win:
        print("  Timed out waiting for the RDP window.")
        print("  Complete any login prompt in Remote Desktop, then press [U] again.")
        return

    hwnd, title, pid = win
    print(f"  RDP session connected/window found: {title}")
    try:
        import ctypes

        ctypes.windll.user32.ShowWindow(hwnd, 9)
    except Exception:
        pass

    def grab():
        return capture_rdp_session_frame(ip)

    try:
        img, meta = grab()
        path = save_ui_capture(img, f"rdp_{ip.replace('.', '_')}")
        print(f"  RDP snapshot saved: {path}")
    except Exception as exc:
        log(f"RDP snapshot failed: {exc}", log_path)

    live_ui_viewer(
        grab,
        title=f"RDP SESSION - {friendly} ({ip})",
        subtitle="Live Remote Desktop view in your browser - watch threat movement on screen",
        log_path=log_path,
        mode="rdp",
        badge="RDP live session",
    )


def focus_process_window(pid: Optional[int]) -> str:
    """Bring a local process window to the foreground so its UI is visible."""
    if not is_windows() or not pid:
        return ""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    wins = windows_for_pid(pid)
    if not wins:
        return ""
    hwnd, title = wins[0]
    try:
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        user32.SetForegroundWindow(hwnd)
        return title
    except Exception:
        return title


def _ui_viewer_html(headline: str, subtitle: str, *, mode: str = "ui", badge: str = "") -> bytes:
    # Escaped for HTML text nodes only (we control these strings)
    def esc(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    is_rdp = mode == "rdp"
    badge_text = badge or ("RDP live session" if is_rdp else "Live compromised-device screen")
    accent = "#1b6ec2" if is_rdp else "#c41e3a"
    accent2 = "#0b3d6e" if is_rdp else "#7a1020"
    footer = (
        "This browser tab mirrors the Remote Desktop session so you can watch threat movement. "
        "Use the Windows Remote Desktop window if you need to type/click. "
        "Return to Network Guard and press Enter when finished, then Kill / Block / Allow."
        if is_rdp
        else
        "This browser tab is your viewer. Leave it open to watch the screen. "
        "Return to the Network Guard console and press Enter when finished, then choose Kill / Block / Allow."
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{'RDP Session' if is_rdp else 'Network Guard Live UI'} - {esc(headline)}</title>
  <style>
    :root {{ color-scheme: dark; }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; font-family: Segoe UI, system-ui, sans-serif;
      background: #0b0d10; color: #f2f4f8;
    }}
    header {{
      position: sticky; top: 0; z-index: 5;
      background: linear-gradient(90deg, {accent2}, {accent} 42%, {accent2});
      padding: 14px 18px; border-bottom: 3px solid #ffd166;
      box-shadow: 0 8px 24px rgba(0,0,0,.45);
    }}
    .badge {{
      display: inline-block; font-size: 12px; font-weight: 700;
      letter-spacing: .08em; text-transform: uppercase;
      background: #111; color: #ffd166; padding: 4px 10px; border-radius: 4px;
    }}
    h1 {{ margin: 8px 0 4px; font-size: 28px; line-height: 1.15; }}
    .sub {{ opacity: .92; font-size: 15px; }}
    .meta {{ margin-top: 8px; font-size: 13px; opacity: .85; }}
    .rdp-chrome {{
      margin: 16px auto 0; width: min(100%, 1400px);
      background: #1a1f29; border: 1px solid #2f3848; border-radius: 12px;
      overflow: hidden; box-shadow: 0 12px 40px rgba(0,0,0,.35);
    }}
    .rdp-bar {{
      display: flex; align-items: center; gap: 10px;
      background: #12161e; padding: 10px 14px; border-bottom: 1px solid #2a3140;
      font-size: 13px;
    }}
    .dot {{ width: 10px; height: 10px; border-radius: 50%; background: #3ddc97; box-shadow: 0 0 8px #3ddc97; }}
    .rdp-bar .addr {{ color: #9ecbff; font-family: Consolas, monospace; }}
    main {{ padding: 16px; display: flex; justify-content: center; }}
    .frame-wrap {{ background: #000; }}
    img#screen {{
      display: block; width: 100%; height: auto; background: #000; min-height: 280px;
    }}
    footer {{
      text-align: center; padding: 12px 16px 24px; color: #9aa3b2; font-size: 13px;
      max-width: 900px; margin: 0 auto;
    }}
  </style>
</head>
<body>
  <header>
    <div class="badge">{esc(badge_text)}</div>
    <h1 id="headline">{esc(headline)}</h1>
    <div class="sub" id="subtitle">{esc(subtitle)}</div>
    <div class="meta" id="meta">Connecting RDP live feed...</div>
  </header>
  <main>
    <div class="rdp-chrome">
      <div class="rdp-bar">
        <div class="dot" title="session live"></div>
        <strong>Remote Desktop</strong>
        <span class="addr" id="addr">{esc(headline)}</span>
        <span style="margin-left:auto;opacity:.75">browser mirror of threat session</span>
      </div>
      <div class="frame-wrap">
        <img id="screen" alt="Live RDP / screen session from the flagged device"/>
      </div>
    </div>
  </main>
  <footer>{esc(footer)}</footer>
  <script>
    const img = document.getElementById('screen');
    const meta = document.getElementById('meta');
    async function tick() {{
      try {{
        const r = await fetch('/meta?ts=' + Date.now());
        if (r.ok) {{
          const j = await r.json();
          if (j.label) meta.textContent = 'LIVE RDP  |  ' + j.label + '  |  updated ' + new Date().toLocaleTimeString();
          if (j.headline) {{
            document.getElementById('headline').textContent = j.headline;
            document.getElementById('addr').textContent = j.headline;
          }}
          if (j.subtitle) document.getElementById('subtitle').textContent = j.subtitle;
        }}
      }} catch (e) {{}}
      img.src = '/frame.jpg?ts=' + Date.now();
    }}
    img.onerror = () => {{ meta.textContent = 'Waiting for next RDP frame...'; }};
    tick();
    setInterval(tick, 700);
  </script>
</body>
</html>
"""
    return html.encode("utf-8")


def live_ui_viewer(
    grab_fn,
    title: str,
    log_path: Path,
    interval_ms: int = 700,
    subtitle: str = "",
    mode: str = "ui",
    badge: str = "",
) -> None:
    """
    Open the default web browser to a live local page showing the compromised UI
    (or an RDP session mirror). Press Enter in the console when finished viewing.
    """
    import threading
    import webbrowser
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    state = {
        "jpeg": b"",
        "label": "starting...",
        "headline": title,
        "subtitle": subtitle
        or (
            "Live Remote Desktop session mirrored in your browser"
            if mode == "rdp"
            else "Watching on-screen activity from the flagged target"
        ),
        "error": "",
        "mode": mode,
        "badge": badge,
    }
    stop = threading.Event()

    def capture_loop() -> None:
        while not stop.is_set():
            try:
                img, label = grab_fn()
                buf = io.BytesIO()
                img.convert("RGB").save(buf, format="JPEG", quality=65, optimize=True)
                state["jpeg"] = buf.getvalue()
                state["label"] = label
                state["error"] = ""
                # Keep a rolling "latest" file for convenience
                try:
                    UI_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
                    latest = UI_CAPTURE_DIR / "latest_live.jpg"
                    latest.write_bytes(state["jpeg"])
                except OSError:
                    pass
            except Exception as exc:  # noqa: BLE001
                state["error"] = str(exc)
                state["label"] = f"capture error: {exc}"
            stop.wait(max(0.2, interval_ms / 1000.0))

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            return

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                body = _ui_viewer_html(
                    state["headline"],
                    state["subtitle"],
                    mode=state["mode"],
                    badge=state["badge"],
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/meta":
                import json as _json

                payload = _json.dumps(
                    {
                        "label": state["label"],
                        "headline": state["headline"],
                        "subtitle": state["subtitle"],
                        "error": state["error"],
                        "mode": state["mode"],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path == "/frame.jpg":
                body = state["jpeg"]
                if not body:
                    self.send_response(503)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"no frame yet")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    # Bind localhost only
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/"

    worker = threading.Thread(target=capture_loop, name="ui-capture", daemon=True)
    worker.start()
    serve_thread = threading.Thread(target=server.serve_forever, daemon=True)
    serve_thread.start()

    # Wait briefly for first frame so the browser isn't empty
    for _ in range(20):
        if state["jpeg"]:
            break
        time.sleep(0.1)

    print()
    if mode == "rdp":
        print("  Opening RDP LIVE SESSION in your web browser...")
    else:
        print("  Opening LIVE UI in your web browser...")
    print(f"  Viewer URL: {url}")
    print("  Leave the browser tab open to watch the screen.")
    print("  When finished, return here and press Enter to continue triage.")
    log(f"UI browser viewer open: {title} -> {url}", log_path)

    opened = False
    try:
        opened = bool(webbrowser.open(url, new=2))
    except Exception as exc:  # noqa: BLE001
        log(f"webbrowser.open failed: {exc}", log_path)
    if not opened and is_windows():
        try:
            subprocess.Popen(["cmd", "/c", "start", "", url], shell=False)
            opened = True
        except OSError:
            pass
    if not opened:
        print(f"  Could not auto-open browser. Paste this URL manually: {url}")

    try:
        input("  Press Enter when done viewing the UI... ")
    except EOFError:
        time.sleep(8)

    stop.set()
    try:
        server.shutdown()
    except Exception:
        pass
    try:
        server.server_close()
    except Exception:
        pass
    print("  Browser UI viewer stopped.")


def view_compromised_ui(
    finding: Connection,
    lan_hosts: List[LanHost],
    log_path: Path,
) -> None:
    """Show the actual on-screen UI of the compromised local process or LAN device."""
    is_lan = finding.proto == "lan"
    device_names = load_device_names()

    if not is_lan:
        if not finding.pid:
            print("  No PID available to capture a window.")
            return

        focused = focus_process_window(finding.pid)
        if focused:
            print(f"  Brought window to foreground: {focused}")
        else:
            print("  No visible window for this process - showing desktop capture in browser.")

        def grab():
            return capture_local_ui(finding.pid)

        try:
            img, meta = grab()
            path = save_ui_capture(img, f"pid{finding.pid}")
            print(f"  Snapshot saved: {path} ({meta})")
            # Also open the still in the default app immediately for clarity
            try:
                if is_windows():
                    os.startfile(path)  # type: ignore[attr-defined]
            except OSError:
                pass
        except Exception as exc:
            log(f"Initial UI capture failed: {exc}", log_path)

        live_ui_viewer(
            grab,
            title=f"{finding.process_name or 'Process'} (PID {finding.pid})",
            subtitle=f"Local threat view - remote {finding.remote_ip}:{finding.remote_port}",
            log_path=log_path,
        )
        return

    # LAN device
    ip = finding.remote_ip
    host = next((h for h in lan_hosts if h.ip == ip), None)
    friendly = (
        device_names.get(ip)
        or (host.hostname if host else "")
        or finding.process_name
        or ip
    )
    token = load_agent_token()
    print()
    print(f"  Attempting to view UI on LAN device {friendly} ({ip}) ...")

    # Prefer RDP browser session when Remote Desktop is available
    rdp_open = False
    if host and 3389 in (host.open_ports or []):
        rdp_open = True
    else:
        rdp_open = tcp_port_open(ip, 3389, timeout=0.5)

    if rdp_open and is_windows():
        print("  RDP (3389) is open - starting Remote Desktop and mirroring it in your browser.")
        start_rdp_browser_session(ip, friendly, log_path)
        return

    if token and agent_reachable(ip, token):
        print("  Network Guard Agent detected - streaming live screen into your browser.")

        def grab_remote():
            img = fetch_agent_screenshot(ip, token)
            return img, f"agent://{ip}:{AGENT_PORT} ({friendly})"

        try:
            img, meta = grab_remote()
            path = save_ui_capture(img, f"lan_{ip.replace('.', '_')}")
            print(f"  Snapshot saved: {path}")
            try:
                if is_windows():
                    os.startfile(path)  # type: ignore[attr-defined]
            except OSError:
                pass
        except Exception as exc:
            log(f"Remote snapshot failed: {exc}", log_path)
        live_ui_viewer(
            grab_remote,
            title=f"{friendly} ({ip})",
            subtitle="LAN device live screen via Network Guard Agent",
            log_path=log_path,
            mode="ui",
            badge="Live agent screen",
        )
        return

    print("  No RDP service and no Network Guard Agent on that device.")
    if not token:
        print(f"  Tip: matching {AGENT_TOKEN_FILE.name} on both PCs enables agent screen view.")
    print("  Options:")
    print("    - Enable Remote Desktop on that Windows PC (port 3389), then press [U] again")
    print("    - Or run run_network_guard_agent.bat on that device, copy agent_token.txt here")
    ans = prompt_choice("  Try opening RDP anyway (may fail if disabled)? [y/N]: ")
    if ans in ("y", "yes") and is_windows():
        start_rdp_browser_session(ip, friendly, log_path)


def triage_finding(
    finding: Connection,
    lan_hosts: List[LanHost],
    *,
    dry_run: bool,
    auto_kill: bool,
    allowlist_path: Path,
    blocklist_path: Path,
    protected_ips: Set[str],
    log_path: Path,
) -> Dict[str, bool]:
    """
    Interactive decision for one finding.
    Returns flags: blocked, killed, allowed, quit
    """
    result = {"blocked": False, "killed": False, "allowed": False, "quit": False}
    show_threat_view(finding, lan_hosts, log_path)

    is_lan = finding.proto == "lan"
    while True:
        print()
        print("  Decide what to do with this threat:")
        print("    [U]  Open RDP/live UI in your web browser (watch threat screen)")
        print("    [V]  View live network activity (connections ~10s)")
        if not is_lan:
            print("    [K]  Kill the process")
        print("    [B]  Block the IP in the firewall")
        if not is_lan:
            print("    [KB] Kill process AND block IP")
        print("    [A]  Allow it (add IP to allowlist, stop flagging)")
        print("    [S]  Skip (do nothing)")
        print("    [Q]  Quit triage (leave remaining findings alone)")
        choice = prompt_choice("  Your choice: ")

        if choice in ("q", "quit"):
            result["quit"] = True
            return result
        if choice in ("s", "skip", ""):
            log(f"SKIP {finding.remote_ip} pid={finding.pid}", log_path)
            return result
        if choice in ("u", "ui", "screen", "desktop"):
            try:
                view_compromised_ui(finding, lan_hosts, log_path)
            except Exception as exc:
                log(f"UI view failed: {exc}", log_path)
                print(f"  UI view failed: {exc}")
            show_threat_view(finding, lan_hosts, log_path)
            continue
        if choice in ("v", "view", "watch"):
            watch_live_activity(finding, 10, log_path)
            show_threat_view(finding, lan_hosts, log_path)
            continue
        if choice in ("a", "allow"):
            target = finding.remote_ip
            if not target or is_local_or_skip(target):
                print("  Nothing to allowlist for this item.")
                continue
            known = load_device_names().get(target, "")
            host = next((h for h in lan_hosts if h.ip == target), None)
            suggested = known or (host.hostname if host else "") or finding.process_name or ""
            if suggested:
                print(f"  Device/host name: {suggested}")
                rename = prompt_choice(
                    f"  Keep this name? Enter for yes, or type a new name: "
                )
                device_name = suggested if rename in ("", "y", "yes") else rename
            else:
                device_name = prompt_choice(
                    "  Name this device/host (e.g. ROKU), or Enter to skip: "
                )
            if dry_run:
                log(
                    f"DRY-RUN would allowlist {target} name={device_name!r} "
                    f"and remember current traffic fingerprint",
                    log_path,
                )
            else:
                append_allowlist(
                    target,
                    allowlist_path,
                    finding=finding,
                    lan_hosts=lan_hosts,
                    device_name=device_name,
                )
                log(
                    f"ALLOWED {target} name={device_name or '-'} "
                    f"(will not ask again unless traffic worsens)",
                    log_path,
                )
            result["allowed"] = True
            return result
        if choice in ("b", "block"):
            if dry_run:
                log(f"DRY-RUN would block {finding.remote_ip}", log_path)
                result["blocked"] = True
                return result
            ok = block_ip(
                finding.remote_ip,
                dry_run=False,
                log_path=log_path,
                allow_private=is_lan or is_private_lan(finding.remote_ip),
                protected=protected_ips,
            )
            if ok:
                append_blocklist(finding.remote_ip, blocklist_path)
                result["blocked"] = True
            return result
        if choice in ("k", "kill") and not is_lan:
            if dry_run:
                log(f"DRY-RUN would kill PID {finding.pid}", log_path)
                result["killed"] = True
                return result
            if kill_process(finding.pid, dry_run=False, log_path=log_path):
                result["killed"] = True
            return result
        if choice in ("kb", "bk", "killblock", "blockkill") and not is_lan:
            if dry_run:
                log(
                    f"DRY-RUN would kill PID {finding.pid} and block {finding.remote_ip}",
                    log_path,
                )
                result["killed"] = True
                result["blocked"] = True
                return result
            if kill_process(finding.pid, dry_run=False, log_path=log_path):
                result["killed"] = True
            if block_ip(
                finding.remote_ip,
                dry_run=False,
                log_path=log_path,
                allow_private=is_private_lan(finding.remote_ip),
                protected=protected_ips,
            ):
                append_blocklist(finding.remote_ip, blocklist_path)
                result["blocked"] = True
            return result

        print("  Invalid choice. Use U / V / K / B / KB / A / S / Q.")


# ---------------------------------------------------------------------------
# LAN discovery + suspicious port probe
# ---------------------------------------------------------------------------

def local_ipv4_addrs() -> List[str]:
    addrs: List[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                addrs.append(ip)
    except OSError:
        pass
    # Also try UDP connect trick for primary egress IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            addrs.append(ip)
    except OSError:
        pass
    # Unique, stable order
    seen: Set[str] = set()
    out: List[str] = []
    for ip in addrs:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def guess_subnet(explicit: Optional[str] = None) -> ipaddress.IPv4Network:
    if explicit:
        return ipaddress.ip_network(explicit, strict=False)  # type: ignore[return-value]

    candidates: List[ipaddress.IPv4Network] = []

    # Prefer Windows Get-NetIPAddress for accurate prefix length
    if is_windows():
        ps = (
            "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } | "
            "Select-Object IPAddress,PrefixLength | ConvertTo-Json -Compress"
        )
        code, out, _ = run_cmd(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            timeout=30,
        )
        if code == 0 and out.strip():
            try:
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    ip = str(item.get("IPAddress", ""))
                    plen = int(item.get("PrefixLength") or 24)
                    if ip and not ip.startswith("127."):
                        net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
                        if net.num_addresses > 256:
                            host = ipaddress.ip_address(ip)
                            net = ipaddress.ip_network(f"{host}/24", strict=False)
                        candidates.append(net)  # type: ignore[arg-type]
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

    # Linux: parse `ip -4 addr`
    if not candidates and shutil.which("ip"):
        code, out, _ = run_cmd(["ip", "-4", "-o", "addr", "show", "scope", "global"])
        if code == 0:
            for line in out.splitlines():
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                if m:
                    net = ipaddress.ip_network(m.group(1), strict=False)
                    if net.num_addresses > 256:
                        host = m.group(1).split("/")[0]
                        net = ipaddress.ip_network(f"{host}/24", strict=False)
                    candidates.append(net)  # type: ignore[arg-type]

    if not candidates:
        addrs = local_ipv4_addrs()
        if not addrs:
            raise RuntimeError("Could not determine local IPv4 address for LAN scan.")
        for ip in addrs:
            candidates.append(ipaddress.ip_network(f"{ip}/24", strict=False))  # type: ignore[arg-type]

    # Prefer the subnet that contains the default gateway (real LAN vs Hyper-V/WSL/vEthernet)
    gw = default_gateway()
    if gw:
        try:
            gw_addr = ipaddress.ip_address(gw)
            for net in candidates:
                if gw_addr in net:
                    return net  # type: ignore[return-value]
        except ValueError:
            pass

    # Prefer common home LAN ranges over virtual switch ranges
    def score(net: ipaddress.IPv4Network) -> int:
        s = str(net)
        if s.startswith("192.168."):
            return 0
        if s.startswith("10."):
            return 1
        if s.startswith("172."):
            return 2
        return 3

    candidates.sort(key=score)
    return candidates[0]  # type: ignore[return-value]


def default_gateway() -> Optional[str]:
    if is_windows():
        code, out, _ = run_cmd(["route", "print", "0.0.0.0"])
        if code == 0:
            for line in out.splitlines():
                parts = re.split(r"\s+", line.strip())
                if len(parts) >= 3 and parts[0] == "0.0.0.0":
                    gw = parts[2]
                    try:
                        ipaddress.ip_address(gw)
                        return gw
                    except ValueError:
                        continue
    if shutil.which("ip"):
        code, out, _ = run_cmd(["ip", "route", "show", "default"])
        if code == 0:
            m = re.search(r"default via (\S+)", out)
            if m:
                return m.group(1)
    return None


def ping_host(ip: str, timeout_ms: int = 400) -> bool:
    if is_windows():
        # -n 1 one echo; -w timeout ms
        code, _, _ = run_cmd(["ping", "-n", "1", "-w", str(timeout_ms), ip], timeout=5)
    else:
        sec = max(1, int(round(timeout_ms / 1000.0)))
        code, _, _ = run_cmd(["ping", "-c", "1", "-W", str(sec), ip], timeout=5)
    return code == 0


def parse_arp_table() -> Dict[str, str]:
    """Return {ip: mac} from the ARP cache."""
    mapping: Dict[str, str] = {}
    code, out, _ = run_cmd(["arp", "-a"])
    if code != 0:
        return mapping
    for line in out.splitlines():
        # Windows:  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
        # Linux:    hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
        m = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}"
            r"[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
            line,
        )
        if not m:
            m = re.search(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+"
                r"([0-9a-fA-F:]{11,17})",
                line,
            )
        if m:
            mapping[m.group(1)] = m.group(2).replace("-", ":").lower()
    return mapping


def tcp_port_open(ip: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolve_hostname(ip: str) -> str:
    """Best-effort device/host name: devices.txt, DNS, NetBIOS."""
    names = load_device_names()
    if ip in names:
        return names[ip]

    try:
        name, _, _ = socket.gethostbyaddr(ip)
        if name:
            # Strip domain suffix noise for display if it's a short label
            short = name.split(".")[0]
            return name if len(name) < 48 else short
    except OSError:
        pass

    if is_windows():
        code, out, _ = run_cmd(["nbtstat", "-A", ip], timeout=8)
        if code == 0:
            # <00> UNIQUE names are often the computer name
            for line in out.splitlines():
                if "<00>" in line and "UNIQUE" in line.upper():
                    part = line.strip().split()
                    if part:
                        cand = part[0].strip()
                        if cand and cand.upper() not in ("MAC", "NODE"):
                            return cand
    else:
        # avahi / getent if present
        if shutil.which("avahi-resolve-address"):
            code, out, _ = run_cmd(["avahi-resolve-address", ip], timeout=5)
            if code == 0 and out.strip():
                parts = out.split()
                if len(parts) >= 2:
                    return parts[-1]
    return ""


def probe_host_ports(
    ip: str,
    ports: Sequence[int],
    timeout: float,
) -> List[int]:
    open_ports: List[int] = []
    for port in ports:
        if tcp_port_open(ip, port, timeout=timeout):
            open_ports.append(port)
    return open_ports


def discover_lan_hosts(
    network: ipaddress.IPv4Network,
    log_path: Path,
    workers: int = 64,
    ping_timeout_ms: int = 350,
) -> List[str]:
    self_ips = set(local_ipv4_addrs())
    candidates = [
        str(h)
        for h in network.hosts()
        if str(h) not in self_ips
    ]
    log(
        f"LAN discovery on {network} ({len(candidates)} hosts, {workers} workers)...",
        log_path,
    )
    live: Set[str] = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(ping_host, ip, ping_timeout_ms): ip for ip in candidates}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            ip = futs[fut]
            try:
                if fut.result():
                    live.add(ip)
            except Exception:
                pass
            if done % 50 == 0 or done == len(futs):
                log(f"  ping progress {done}/{len(futs)} — live so far: {len(live)}", log_path)

    # Merge ARP (catches hosts that ignore ICMP but are active)
    for ip, _mac in parse_arp_table().items():
        try:
            if ipaddress.ip_address(ip) in network and ip not in self_ips:
                live.add(ip)
        except ValueError:
            continue

    ordered = sorted(live, key=lambda x: tuple(int(p) for p in x.split(".")))
    log(f"Discovered {len(ordered)} live host(s) on LAN.", log_path)
    return ordered


def scan_lan(
    network: ipaddress.IPv4Network,
    allowlist: Set[str],
    blocklist: Set[str],
    log_path: Path,
    workers: int = 32,
    port_timeout: float = 0.35,
    ports: Sequence[int] = LAN_PROBE_PORTS,
    allow_state: Optional[Dict[str, dict]] = None,
    state_path: Path = DEFAULT_ALLOW_STATE,
) -> List[LanHost]:
    gw = default_gateway()
    self_ips = set(local_ipv4_addrs())
    live = discover_lan_hosts(network, log_path, workers=max(workers, 32))
    arp = parse_arp_table()
    device_names = load_device_names()
    state = allow_state if allow_state is not None else load_allow_state(state_path)

    results: List[LanHost] = []

    def scan_one(ip: str) -> LanHost:
        resolved = resolve_hostname(ip)
        friendly = device_names.get(ip) or resolved
        host = LanHost(
            ip=ip,
            hostname=friendly,
            mac=arp.get(ip, ""),
            is_gateway=(ip == gw),
            is_self=(ip in self_ips),
        )
        host.open_ports = probe_host_ports(ip, ports, timeout=port_timeout)

        if ip_in_list(ip, blocklist):
            host.reasons.append("IP on blocklist")

        bad_open = [p for p in host.open_ports if p in SUSPICIOUS_LISTEN_PORTS or p in (23, 2323, 7547)]
        if bad_open:
            host.reasons.append(
                "suspicious open port(s): " + ",".join(str(p) for p in bad_open)
            )
        risky_extra = [p for p in host.open_ports if p in (5555, 49152) and p not in bad_open]
        if risky_extra:
            host.reasons.append(
                "risky service port(s): " + ",".join(str(p) for p in risky_extra)
            )

        if host.reasons:
            fp = {
                "name": host.hostname or "",
                "allowed_at": dt.datetime.now().isoformat(timespec="seconds"),
                "ports": list(host.open_ports),
                "suspicious_ports": suspicious_ports_from_open(host.open_ports),
                "reasons": list(host.reasons),
                "remote_port": host.open_ports[0] if host.open_ports else 0,
                "process_name": host.hostname or "",
                "proto": "lan",
            }
            skip, note = allowlist_should_skip(ip, allowlist, state, fp, state_path)
            if skip:
                host.reasons = []
            elif note.startswith("allowlisted but traffic worsened"):
                host.reasons = [note] + host.reasons
        return host

    log(
        f"Probing {len(live)} host(s) on ports {','.join(str(p) for p in ports)}...",
        log_path,
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(scan_one, ip) for ip in live]
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            try:
                results.append(fut.result())
            except Exception as exc:
                log(f"  host scan error: {exc}", log_path)
            if i % 10 == 0 or i == len(futs):
                log(f"  port-scan progress {i}/{len(futs)}", log_path)

    results.sort(key=lambda h: tuple(int(p) for p in h.ip.split(".")))
    return results


def lan_hosts_to_findings(hosts: List[LanHost]) -> List[Connection]:
    """Adapt LAN findings into Connection objects for shared remediation."""
    findings: List[Connection] = []
    for h in hosts:
        if not h.suspicious or h.is_self:
            continue
        port = h.open_ports[0] if h.open_ports else 0
        findings.append(
            Connection(
                proto="lan",
                local_ip="scan",
                local_port=0,
                remote_ip=h.ip,
                remote_port=port,
                state="LAN_HOST",
                pid=None,
                process_name=h.hostname or h.mac or "lan-host",
                reasons=list(h.reasons),
            )
        )
    return findings


def print_lan_inventory(hosts: List[LanHost]) -> None:
    print()
    print("LAN inventory:")
    print(f"  {'IP':<16} {'Device / Host':<28} {'MAC':<20} Ports / flags")
    print("  " + "-" * 90)
    for h in hosts:
        ports = ",".join(str(p) for p in h.open_ports) if h.open_ports else "-"
        flags = []
        if h.is_gateway:
            flags.append("gateway")
        if h.suspicious:
            flags.append("SUSPICIOUS")
        flag_s = f" [{', '.join(flags)}]" if flags else ""
        print(
            f"  {h.ip:<16} {(h.hostname or '-'):<28} {(h.mac or '-'):<20} "
            f"{ports}{flag_s}"
        )
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def ensure_default_lists() -> None:
    if not DEFAULT_ALLOWLIST.exists():
        DEFAULT_ALLOWLIST.write_text(
            "# One IP or CIDR per line. These are never blocked.\n"
            "# Re-prompt only if traffic gets worse than when you allowed it.\n"
            "# 192.168.1.0/24\n"
            "# 10.0.0.0/8\n",
            encoding="utf-8",
        )
    if not DEFAULT_BLOCKLIST.exists():
        DEFAULT_BLOCKLIST.write_text(
            "# Known-bad IPs / CIDRs. Matching remotes are always flagged.\n",
            encoding="utf-8",
        )
    if not DEFAULT_DEVICES.exists():
        DEFAULT_DEVICES.write_text(
            "# Friendly names for LAN devices (IP then name).\n"
            "# Used in inventory, triage, and allowlist memory.\n"
            "192.168.1.102  ROKU\n",
            encoding="utf-8",
        )


def print_finding(conn: Connection) -> None:
    reasons = "; ".join(conn.reasons)
    print(
        f"  [{conn.proto}] {conn.local_ip}:{conn.local_port} -> "
        f"{conn.remote_ip}:{conn.remote_port}  state={conn.state}  "
        f"pid={conn.pid or '-'}  process={conn.process_name or '-'}  "
        f"reason={reasons}"
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect suspicious network activity and block/remove it."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report only; do not change firewall or kill processes.",
    )
    parser.add_argument(
        "--kill",
        action="store_true",
        help="Also force-terminate processes owning suspicious connections.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Unattended mode: block all findings without asking (use with care).",
    )
    parser.add_argument(
        "--watch",
        type=int,
        metavar="SECONDS",
        default=0,
        help="Rescan every N seconds until Ctrl+C (0 = once).",
    )
    parser.add_argument(
        "--lan",
        action="store_true",
        help="Also discover and scan other devices on the local network.",
    )
    parser.add_argument(
        "--lan-only",
        action="store_true",
        help="Skip local socket scan; only scan LAN devices.",
    )
    parser.add_argument(
        "--subnet",
        default=None,
        help="CIDR to scan (default: auto-detect local subnet, capped at /24).",
    )
    parser.add_argument(
        "--lan-workers",
        type=int,
        default=48,
        help="Parallel workers for LAN ping/port scans (default: 48).",
    )
    parser.add_argument(
        "--lan-port-timeout",
        type=float,
        default=0.35,
        help="Seconds per TCP connect probe (default: 0.35).",
    )
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=DEFAULT_ALLOWLIST,
        help=f"Allowlist file (default: {DEFAULT_ALLOWLIST})",
    )
    parser.add_argument(
        "--blocklist",
        type=Path,
        default=DEFAULT_BLOCKLIST,
        help=f"Blocklist file (default: {DEFAULT_BLOCKLIST})",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=DEFAULT_LOG,
        help=f"Log file (default: {DEFAULT_LOG})",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Write findings JSON to this path.",
    )
    args = parser.parse_args(argv)
    if args.lan_only:
        args.lan = True

    ensure_default_lists()
    log_path: Path = args.log

    log("=" * 60, log_path)
    log(
        f"Network Guard starting on {platform.system()} {platform.release()} "
        f"| Python {platform.python_version()} | admin={is_admin()}",
        log_path,
    )

    if not args.dry_run and not is_admin():
        log(
            "WARNING: Not running as administrator/root. "
            "Firewall blocks and process kills will likely fail. "
            "Re-run elevated, or use --dry-run.",
            log_path,
        )

    protected_ips: Set[str] = set(local_ipv4_addrs())
    gw = default_gateway()
    if gw:
        protected_ips.add(gw)

    def scan_once() -> Tuple[List[Connection], List[LanHost]]:
        allowlist = load_ip_list(args.allowlist)
        blocklist = load_ip_list(args.blocklist)
        findings: List[Connection] = []
        lan_hosts: List[LanHost] = []

        if not args.lan_only:
            log("Scanning local active connections...", log_path)
            conns = enumerate_connections()
            log(f"Enumerated {len(conns)} socket(s).", log_path)
            findings.extend(
                enrich_and_detect(
                    conns,
                    allowlist,
                    blocklist,
                    allow_state=load_allow_state(),
                )
            )

        if args.lan:
            try:
                network = guess_subnet(args.subnet)
            except (RuntimeError, ValueError) as exc:
                log(f"LAN scan skipped: {exc}", log_path)
                return findings, lan_hosts
            log(
                "NOTE: LAN blocks apply on THIS PC only. "
                "To protect phones/TVs/other PCs, also block flagged IPs on your router.",
                log_path,
            )
            lan_hosts = scan_lan(
                network,
                allowlist,
                blocklist,
                log_path,
                workers=max(8, args.lan_workers),
                port_timeout=max(0.1, args.lan_port_timeout),
                allow_state=load_allow_state(),
            )
            print_lan_inventory(lan_hosts)
            for h in lan_hosts:
                log(
                    f"LAN host {h.ip} host={h.hostname or '-'} mac={h.mac or '-'} "
                    f"ports={h.open_ports or '-'} reasons={h.reasons or '-'}",
                    log_path,
                )
            findings.extend(lan_hosts_to_findings(lan_hosts))

        return findings, lan_hosts

    def remediate(findings: List[Connection], lan_hosts: List[LanHost]) -> None:
        if not findings:
            log("No suspicious connections or LAN hosts detected.", log_path)
            return

        log(f"Found {len(findings)} suspicious item(s):", log_path)
        for f in findings:
            print_finding(f)
            log(
                f"FINDING {f.proto} {f.local_ip}:{f.local_port}->{f.remote_ip}:{f.remote_port} "
                f"pid={f.pid} proc={f.process_name} :: {'; '.join(f.reasons)}",
                log_path,
            )

        if args.json_out:
            payload = {
                "findings": [asdict(f) for f in findings],
                "lan_hosts": [asdict(h) for h in lan_hosts],
            }
            args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            log(f"Wrote JSON report: {args.json_out}", log_path)

        if args.dry_run and args.yes:
            log("Dry-run + --yes: report only, no prompts.", log_path)
            return

        blocked: Set[str] = set()
        killed: Set[int] = set()
        allowed: Set[str] = set()

        # Unattended mode: block everything (and kill if --kill)
        if args.yes:
            for f in findings:
                remote = f.remote_ip
                if remote and remote not in blocked:
                    if block_ip(
                        remote,
                        dry_run=args.dry_run,
                        log_path=log_path,
                        allow_private=f.proto == "lan" or is_private_lan(remote),
                        protected=protected_ips,
                    ):
                        blocked.add(remote)
                        if not args.dry_run:
                            append_blocklist(remote, args.blocklist)
                if args.kill and f.pid and f.pid not in killed and f.proto != "lan":
                    if kill_process(f.pid, dry_run=args.dry_run, log_path=log_path):
                        killed.add(f.pid)
        else:
            # Interactive triage: view activity, then kill / block / allow / skip
            print()
            print("Interactive triage: review each threat, then choose an action.")
            print("You can watch live connections before deciding.")
            for idx, f in enumerate(findings, 1):
                print()
                print(f">>> Threat {idx} of {len(findings)}")
                decision = triage_finding(
                    f,
                    lan_hosts,
                    dry_run=args.dry_run,
                    auto_kill=args.kill,
                    allowlist_path=args.allowlist,
                    blocklist_path=args.blocklist,
                    protected_ips=protected_ips,
                    log_path=log_path,
                )
                if decision.get("blocked") and f.remote_ip:
                    blocked.add(f.remote_ip)
                if decision.get("killed") and f.pid:
                    killed.add(f.pid)
                if decision.get("allowed") and f.remote_ip:
                    allowed.add(f.remote_ip)
                if decision.get("quit"):
                    log("Triage quit by user; remaining findings skipped.", log_path)
                    break

        if blocked:
            export = SCRIPT_DIR / "router_block_candidates.txt"
            with export.open("w", encoding="utf-8") as fh:
                fh.write(
                    "# Paste these into your router firewall / parental controls / deny list\n"
                    "# Generated by Network Guard\n"
                )
                for ip in sorted(blocked, key=lambda x: tuple(int(p) for p in x.split("."))):
                    fh.write(ip + "\n")
            log(f"Wrote router block candidates: {export}", log_path)

        log(
            f"Done. Blocked {len(blocked)} IP(s); killed {len(killed)} process(es); "
            f"allowed {len(allowed)} IP(s).",
            log_path,
        )

    try:
        if args.watch and args.watch > 0:
            log(f"Watch mode every {args.watch}s (Ctrl+C to stop).", log_path)
            while True:
                findings, lan_hosts = scan_once()
                remediate(findings, lan_hosts)
                time.sleep(args.watch)
        else:
            findings, lan_hosts = scan_once()
            remediate(findings, lan_hosts)
    except KeyboardInterrupt:
        log("Interrupted.", log_path)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
