#!/usr/bin/env python3
"""
Network Guard — detect suspicious network activity, block remote IPs,
and optionally terminate offending processes.

Works on Windows and Linux (Python 3.7+). Requires administrator/root
for firewall changes and process termination.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
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
from typing import Iterable, List, Optional, Sequence, Set, Tuple

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

    if remote and not is_local_or_skip(remote) and ip_in_list(remote, allowlist):
        return reasons

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
) -> List[Connection]:
    findings: List[Connection] = []
    seen: Set[str] = set()
    for conn in connections:
        if not conn.process_name and conn.pid:
            conn.process_name = process_name_for_pid(conn.pid)
        reasons = score_connection(conn, allowlist, blocklist)
        if not reasons:
            continue
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


def block_ip(ip: str, dry_run: bool, log_path: Path) -> bool:
    if is_local_or_skip(ip) or is_private_lan(ip):
        log(f"Refusing to block local/private address {ip}", log_path)
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def ensure_default_lists() -> None:
    if not DEFAULT_ALLOWLIST.exists():
        DEFAULT_ALLOWLIST.write_text(
            "# One IP or CIDR per line. These are never blocked.\n"
            "# 192.168.1.0/24\n"
            "# 10.0.0.0/8\n",
            encoding="utf-8",
        )
    if not DEFAULT_BLOCKLIST.exists():
        DEFAULT_BLOCKLIST.write_text(
            "# Known-bad IPs / CIDRs. Matching remotes are always flagged.\n",
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
        help="Apply blocks without interactive confirmation.",
    )
    parser.add_argument(
        "--watch",
        type=int,
        metavar="SECONDS",
        default=0,
        help="Rescan every N seconds until Ctrl+C (0 = once).",
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

    def scan_once() -> List[Connection]:
        allowlist = load_ip_list(args.allowlist)
        blocklist = load_ip_list(args.blocklist)
        log("Scanning active connections...", log_path)
        conns = enumerate_connections()
        log(f"Enumerated {len(conns)} socket(s).", log_path)
        findings = enrich_and_detect(conns, allowlist, blocklist)
        return findings

    def remediate(findings: List[Connection]) -> None:
        if not findings:
            log("No suspicious connections detected.", log_path)
            return

        log(f"Found {len(findings)} suspicious connection(s):", log_path)
        for f in findings:
            print_finding(f)
            log(
                f"FINDING {f.proto} {f.local_ip}:{f.local_port}->{f.remote_ip}:{f.remote_port} "
                f"pid={f.pid} proc={f.process_name} :: {'; '.join(f.reasons)}",
                log_path,
            )

        if args.json_out:
            payload = [asdict(f) for f in findings]
            args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            log(f"Wrote JSON report: {args.json_out}", log_path)

        if args.dry_run:
            log("Dry-run mode: no blocks or kills applied.", log_path)
            return

        if not args.yes:
            try:
                answer = input("Block flagged remote IPs now? [y/N]: ").strip().lower()
            except EOFError:
                answer = "n"
            if answer not in ("y", "yes"):
                log("Aborted by user; no changes made.", log_path)
                return

        blocked: Set[str] = set()
        killed: Set[int] = set()
        for f in findings:
            remote = f.remote_ip
            if remote and not is_local_or_skip(remote) and remote not in blocked:
                if block_ip(remote, dry_run=False, log_path=log_path):
                    blocked.add(remote)
                    append_blocklist(remote, args.blocklist)
            if args.kill and f.pid and f.pid not in killed:
                if kill_process(f.pid, dry_run=False, log_path=log_path):
                    killed.add(f.pid)

        log(
            f"Done. Blocked {len(blocked)} IP(s); terminated {len(killed)} process(es).",
            log_path,
        )

    try:
        if args.watch and args.watch > 0:
            log(f"Watch mode every {args.watch}s (Ctrl+C to stop).", log_path)
            while True:
                remediate(scan_once())
                time.sleep(args.watch)
        else:
            remediate(scan_once())
    except KeyboardInterrupt:
        log("Interrupted.", log_path)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
