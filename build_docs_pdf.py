#!/usr/bin/env python3
"""Generate Network Guard documentation PDF for GitHub."""

from pathlib import Path

from PIL import Image as PILImage
from reportlab.lib.colors import HexColor, white
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "Network_Guard_Documentation.pdf"
CARD = ROOT / "github_card.png"
ACCENT = HexColor("#0969da")
DARK = HexColor("#1f2328")
MUTED = HexColor("#656d76")
BORDER = HexColor("#d0d7de")
SOFT = HexColor("#f6f8fa")


def styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "NGTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=DARK,
            spaceAfter=6,
            alignment=TA_CENTER,
        ),
        "sub": ParagraphStyle(
            "NGSub",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=11,
            textColor=MUTED,
            alignment=TA_CENTER,
            spaceAfter=14,
        ),
        "h1": ParagraphStyle(
            "NGH1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=14,
            textColor=ACCENT,
            spaceBefore=14,
            spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "NGH2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=DARK,
            spaceBefore=10,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "NGBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=DARK,
            alignment=TA_JUSTIFY,
            spaceAfter=8,
        ),
        "bullet": ParagraphStyle(
            "NGBullet",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=DARK,
            leftIndent=8,
        ),
        "mono": ParagraphStyle(
            "NGMono",
            parent=base["Code"],
            fontName="Courier",
            fontSize=8.5,
            leading=11,
            textColor=DARK,
            backColor=SOFT,
            leftIndent=6,
            rightIndent=6,
            spaceBefore=4,
            spaceAfter=8,
        ),
        "caption": ParagraphStyle(
            "NGCap",
            parent=base["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=9,
            textColor=MUTED,
            alignment=TA_CENTER,
            spaceBefore=4,
            spaceAfter=12,
        ),
        "footer": ParagraphStyle(
            "NGFoot",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=MUTED,
            alignment=TA_CENTER,
        ),
    }


def bullets(items, sty):
    return ListFlowable(
        [ListItem(Paragraph(i, sty["bullet"]), leftIndent=12, bulletColor=ACCENT) for i in items],
        bulletType="bullet",
        start="•",
        leftIndent=18,
        spaceBefore=2,
        spaceAfter=8,
    )


def card_image(path: Path, max_w=5.8 * inch):
    img = PILImage.open(path)
    w, h = img.size
    scale = max_w / float(w)
    return Image(str(path), width=max_w, height=h * scale)


def build():
    sty = styles()
    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
        title="Network Guard - Full Documentation",
        author="Pilisi W",
    )
    story = []

    story.append(Paragraph("Network Guard", sty["title"]))
    story.append(
        Paragraph(
            "Full Product Explanation for GitHub &amp; Operators<br/>"
            "Author: Pilisi W &nbsp;|&nbsp; Year: 2026 &nbsp;|&nbsp; "
            "Repository: github.com/pelishminer2-ui/network-guard",
            sty["sub"],
        )
    )

    # Screenshot area
    story.append(Paragraph("1. GitHub Project Card (Screenshot)", sty["h1"]))
    story.append(
        Paragraph(
            "The public repository card summarizes the project at a glance: name, "
            "visibility, one-line purpose, and primary language.",
            sty["body"],
        )
    )
    if CARD.exists():
        story.append(card_image(CARD))
        story.append(
            Paragraph(
                "Figure 1. GitHub repository card for <b>network-guard</b> "
                "(Public · Python · Detect suspicious network activity and block remote IPs "
                "on Windows and Linux).",
                sty["caption"],
            )
        )

    story.append(Paragraph("2. What This Project Is", sty["h1"]))
    story.append(
        Paragraph(
            "<b>Network Guard</b> is a defensive security utility written in Python. "
            "It helps an operator (threat analyst) discover suspicious network activity "
            "on the local computer and on other devices on the same private LAN, explain "
            "what open ports normally mean, optionally watch activity quietly, and then "
            "decide whether to <b>kill</b> a local process, <b>block</b> an IP in the "
            "firewall, <b>allow</b> it (with memory so unchanged traffic is not asked "
            "about again), or <b>skip</b>.",
            sty["body"],
        )
    )
    story.append(
        Paragraph(
            "It is intended for systems and networks you administer. Blocking performed "
            "on one PC protects that PC. Protecting every device on the LAN also "
            "requires router-level blocks (a helper file of candidate IPs is written) "
            "or installing the companion agent on other machines.",
            sty["body"],
        )
    )

    story.append(Paragraph("3. Main Components", sty["h1"]))
    rows = [
        [Paragraph("<b>File</b>", sty["bullet"]), Paragraph("<b>Role</b>", sty["bullet"])],
        [
            Paragraph("network_guard.py", sty["bullet"]),
            Paragraph(
                "Core scanner, triage UI, port glossary, allowlist memory, quiet watch, "
                "firewall remediation.",
                sty["bullet"],
            ),
        ],
        [
            Paragraph("run_network_guard.bat", sty["bullet"]),
            Paragraph("Windows launcher; elevates to Administrator and runs with --lan.", sty["bullet"]),
        ],
        [
            Paragraph("run_network_guard.sh", sty["bullet"]),
            Paragraph("Linux launcher; uses sudo and --lan.", sty["bullet"]),
        ],
        [
            Paragraph("network_guard_agent.py", sty["bullet"]),
            Paragraph(
                "Optional agent on other owned PCs; shares screen frames (token-protected) "
                "for quiet watch.",
                sty["bullet"],
            ),
        ],
        [
            Paragraph("run_network_guard_agent.bat", sty["bullet"]),
            Paragraph("Windows launcher for the agent.", sty["bullet"]),
        ],
        [
            Paragraph("allowlist.txt / blocklist.txt", sty["bullet"]),
            Paragraph("Trusted and known-bad IPs/CIDRs.", sty["bullet"],),
        ],
        [
            Paragraph("devices.txt", sty["bullet"]),
            Paragraph("Friendly names (example: 192.168.1.102 → ROKU).", sty["bullet"]),
        ],
        [
            Paragraph("allowlist_state.json", sty["bullet"]),
            Paragraph(
                "Local fingerprint of allowed traffic; re-prompt only if activity worsens.",
                sty["bullet"],
            ),
        ],
    ]
    t = Table(rows, colWidths=[2.1 * inch, 4.5 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), SOFT),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 8))

    story.append(Paragraph("4. End-to-End Workflow", sty["h1"]))
    story.append(Paragraph("4.1 Launch", sty["h2"]))
    story.append(
        Paragraph(
            "On Windows, double-click the desktop shortcut or "
            "<font face='Courier'>run_network_guard.bat</font>. The BAT requests "
            "Administrator rights (needed for firewall rules), then runs "
            "<font face='Courier'>network_guard.py --lan</font> in interactive triage "
            "mode. On Linux, <font face='Courier'>run_network_guard.sh</font> re-launches "
            "with sudo.",
            sty["body"],
        )
    )

    story.append(Paragraph("4.2 Local socket scan", sty["h2"]))
    story.append(
        Paragraph(
            "The script enumerates active TCP/UDP sockets (PowerShell "
            "Get-NetTCPConnection / netstat on Windows; ss / netstat on Linux), "
            "resolves owning process names, and scores each connection with heuristics:",
            sty["body"],
        )
    )
    story.append(
        bullets(
            [
                "Connections to or from ports commonly used by backdoors, reverse shells, "
                "proxies, VNC, Tor, or historic Trojans (for example 4444, 31337, 12345).",
                "Suspicious listening ports on the local machine.",
                "Exact matches on known abusive tool process names (for example netcat, "
                "meterpreter) — exact name match only, to avoid false positives.",
                "IPs present on the operator blocklist.",
            ],
            sty,
        )
    )

    story.append(Paragraph("4.3 LAN discovery and port probe", sty["h2"]))
    story.append(
        Paragraph(
            "With <font face='Courier'>--lan</font>, Network Guard auto-detects the home "
            "subnet (preferring the network that contains the default gateway, so Hyper-V "
            "/ WSL virtual adapters are not chosen by mistake). It pings hosts in parallel, "
            "merges ARP cache entries, resolves names (devices.txt, DNS, NetBIOS), and "
            "probes a focused set of risky/admin ports. Results appear in a LAN inventory "
            "table with device names (for example ROKU).",
            sty["body"],
        )
    )

    story.append(Paragraph("4.4 Port meanings for the analyst", sty["h2"]))
    story.append(
        Paragraph(
            "Every flagged or open port is explained in plain English so the person "
            "detecting threats understands normal use — for example "
            "<b>3389 = Remote Desktop (RDP)</b>, "
            "<b>8080 = Alternate HTTP / device admin pages</b>, "
            "<b>4444 = Common Metasploit/meterpreter listener port</b>. "
            "Explanations appear in the LAN inventory, finding lines, threat reasons, "
            "and the Threat View panel.",
            sty["body"],
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("4.5 Interactive triage", sty["h1"]))
    story.append(
        Paragraph(
            "For each finding, Network Guard shows a <b>Threat View</b> (process path, "
            "command line, window title when available, connections, DNS, device name, "
            "MAC, open ports and meanings). The operator then chooses:",
            sty["body"],
        )
    )
    story.append(
        bullets(
            [
                "<b>[U] Quiet watch</b> — browser live view with no RDP and no window focus "
                "steal. Local threats are captured in the background; LAN screens require "
                "the Network Guard Agent already installed on that owned PC. Loud RDP "
                "mirroring is optional and asked only if RDP is open.",
                "<b>[V] Network-only watch</b> — observe new remote endpoints for ~10 seconds "
                "without screen capture.",
                "<b>[K] Kill</b> — terminate the local offending process (not used for "
                "remote LAN hosts).",
                "<b>[B] Block</b> — add Windows Firewall or Linux nft/iptables/ufw drop "
                "rules for the remote IP (gateway and this PC’s own IPs are protected).",
                "<b>[KB] Kill and block</b> — both actions for local threats.",
                "<b>[A] Allow</b> — add IP to allowlist, optional device name, and save a "
                "traffic fingerprint so the same behavior is not re-asked unless it gets "
                "worse (new suspicious ports/reasons).",
                "<b>[S] Skip</b> / <b>[Q] Quit</b> triage.",
            ],
            sty,
        )
    )

    story.append(Paragraph("4.6 Quiet watch details", sty["h2"]))
    story.append(
        Paragraph(
            "Quiet mode is the default for <b>[U]</b>. It opens the operator’s default "
            "web browser to a local live page that streams captured frames. It does "
            "<b>not</b> create a Remote Desktop login session by default, and it does "
            "not raise the threat’s window to the foreground. That keeps watching from "
            "announcing itself via an interactive RDP session. Passwordless RDP, "
            "credential brute force, and hidden unauthorized RDP are intentionally "
            "not part of this tool.",
            sty["body"],
        )
    )

    story.append(Paragraph("4.7 Remediation artifacts", sty["h2"]))
    story.append(
        bullets(
            [
                "Firewall rules named with a NetworkGuard prefix.",
                "Appended entries in blocklist.txt or allowlist.txt.",
                "allowlist_state.json fingerprints for stable allow decisions.",
                "router_block_candidates.txt listing IPs to paste into router deny lists.",
                "ui_captures/ snapshots and latest_live.jpg from watch sessions.",
                "network_guard.log for an audit trail.",
            ],
            sty,
        )
    )

    story.append(Paragraph("5. How Detection Heuristics Work", sty["h1"]))
    story.append(
        Paragraph(
            "Detection is signature/heuristic based, not a full IDS. It prioritizes "
            "high-signal ports and process names associated with remote access abuse "
            "and classic malware listeners, while allowing operators to teach the tool "
            "about trusted devices (ROKU, printers, NAS) via allowlist + devices.txt. "
            "Allowlisted hosts are remembered; only negative change (worse ports or new "
            "threat reasons) brings them back for triage.",
            sty["body"],
        )
    )

    story.append(Paragraph("6. Platform Support", sty["h1"]))
    story.append(
        bullets(
            [
                "<b>Windows</b> — netsh advfirewall blocks; taskkill; PowerShell/netstat "
                "enumeration; optional mstsc RDP mirror (loud, opt-in).",
                "<b>Linux</b> — nftables / iptables / ufw; kill; ss/netstat.",
                "<b>Python 3.7+</b> recommended; Pillow used for screen capture / PDF assets; "
                "stdlib otherwise for core scanning.",
            ],
            sty,
        )
    )

    story.append(Paragraph("7. Typical Operator Commands", sty["h1"]))
    story.append(
        Paragraph(
            "Interactive LAN + local scan (default from BAT):",
            sty["body"],
        )
    )
    story.append(Paragraph("python network_guard.py --lan", sty["mono"]))
    story.append(Paragraph("Report only (no firewall changes):", sty["body"]))
    story.append(Paragraph("python network_guard.py --lan --dry-run", sty["mono"]))
    story.append(Paragraph("Unattended auto-block (use carefully):", sty["body"]))
    story.append(Paragraph("python network_guard.py --lan --yes", sty["mono"]))
    story.append(Paragraph("LAN devices only:", sty["body"]))
    story.append(Paragraph("python network_guard.py --lan-only", sty["mono"]))

    story.append(Paragraph("8. Security &amp; Scope Notes (for GitHub readers)", sty["h1"]))
    story.append(
        bullets(
            [
                "Run only on networks and devices you are authorized to administer.",
                "Administrator/root is required for real firewall blocks and process kills.",
                "False positives are possible; use allowlist and review port meanings before blocking.",
                "Agent screen sharing requires a shared token file; treat tokens as secrets "
                "(agent_token.txt is gitignored).",
                "This project does not implement credential attacks or stealth unauthorized RDP.",
            ],
            sty,
        )
    )

    story.append(Paragraph("9. Summary", sty["h1"]))
    story.append(
        Paragraph(
            "In one sentence: <b>Network Guard</b> is a Python defensive tool that scans "
            "this PC and your LAN for suspicious sockets and open ports, explains those "
            "ports to the analyst, offers quiet browser watching via local capture or an "
            "optional agent, and lets you interactively kill, block, allow, or skip each "
            "threat — with allowlist memory so stable trusted devices are not nagged again.",
            sty["body"],
        )
    )
    story.append(Spacer(1, 16))
    story.append(
        Paragraph(
            "Network Guard Documentation · Pilisi W · 2026 · Public GitHub repository network-guard",
            sty["footer"],
        )
    )

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(0.75 * inch, 0.5 * inch, letter[0] - 0.75 * inch, 0.5 * inch)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(0.75 * inch, 0.35 * inch, "network-guard · Pilisi W · 2026")
        canvas.drawRightString(letter[0] - 0.75 * inch, 0.35 * inch, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    build()
