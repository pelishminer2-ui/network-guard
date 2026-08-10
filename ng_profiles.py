#!/usr/bin/env python3
"""Known-good device profiles to reduce false positives."""

from __future__ import annotations

from typing import Dict, List, Set

# vendor/keyword -> ports considered normal for that class
PROFILES: Dict[str, Set[int]] = {
    "roku": {8060, 8080, 8888, 80, 443},
    "amazon": {80, 443, 8009, 8080},
    "printer": {80, 443, 631, 9100, 515, 161},
    "hp": {80, 443, 631, 9100, 515},
    "canon": {80, 443, 631, 9100},
    "epson": {80, 443, 631, 9100},
    "nas": {80, 443, 445, 139, 22, 5000, 5001, 8080},
    "synology": {80, 443, 5000, 5001, 22, 445},
    "qnap": {80, 443, 8080, 22, 445},
    "router": {80, 443, 53, 67, 68},
    "netgear": {80, 443},
    "tp-link": {80, 443},
    "ubiquiti": {80, 443, 8080, 8443},
    "apple": {80, 443, 5353, 7000},
    "google": {80, 443, 8008, 8009},
    "raspberry": {22, 80, 443},
    "sonos": {80, 443, 1400, 3400, 3401},
}


def profile_ports_for_label(label: str) -> Set[int]:
    low = (label or "").lower()
    ports: Set[int] = set()
    for key, vals in PROFILES.items():
        if key in low:
            ports |= vals
    return ports


def is_port_expected(label: str, port: int) -> bool:
    return int(port) in profile_ports_for_label(label)


def filter_unexpected_ports(label: str, ports: List[int]) -> List[int]:
    expected = profile_ports_for_label(label)
    if not expected:
        return list(ports)
    return [p for p in ports if p not in expected]
