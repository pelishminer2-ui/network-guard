#!/usr/bin/env python3
"""MAC OUI vendor lookup for Network Guard."""

from __future__ import annotations

from typing import Dict

# Compact high-value OUI map (lowercase, no separators in key = first 6 hex)
OUI_VENDORS: Dict[str, str] = {
    "7c67ab": "Roku",
    "b8a175": "Roku",
    "dc3a5e": "Roku",
    "d83134": "Roku",
    "acae19": "Roku",
    "cc6da0": "Roku",
    "001a11": "Google",
    "f4f5e8": "Google",
    "3c5ab4": "Google",
    "54efa3": "Amazon",
    "0c47c9": "Amazon",
    "44650d": "Amazon",
    "68a40e": "Amazon",
    "fc65de": "Amazon",
    "a4c138": "Apple",
    "f0d1a9": "Apple",
    "ac87a3": "Apple",
    "28e02c": "Apple",
    "bc926b": "Apple",
    "001d7e": "Cisco-Linksys",
    "001e13": "Cisco",
    "00a0c9": "Intel",
    "3c970e": "Intel",
    "001b63": "Apple",
    "000c29": "VMware",
    "005056": "VMware",
    "00155d": "Microsoft Hyper-V",
    "000d3a": "Microsoft",
    "7c83ff": "Samsung",
    "001632": "Samsung",
    "8cc121": "Panasonic",
    "b827eb": "Raspberry Pi",
    "dca632": "Raspberry Pi",
    "e45f01": "Raspberry Pi",
    "001e06": "Wyse/Dell",
    "0026b9": "Dell",
    "d4bed9": "Dell",
    "001e58": "D-Link",
    "1c7ee5": "D-Link",
    "c0a0bb": "D-Link",
    "0014d1": "TRENDnet",
    "002722": "Ubiquiti",
    "24161b": "Ubiquiti",
    "f09fc2": "Ubiquiti",
    "b4fbe4": "Ubiquiti",
    "44d9e7": "Ubiquiti",
    "18e829": "Ubiquiti",
    "000b82": "Grandstream",
    "0004f2": "Polycom",
    "00e098": "HME/Network",
    "000a66": "Hewlett Packard",
    "001a4b": "HP",
    "3cd92b": "HP",
    "9457a5": "HP",
    "001e0b": "HP",
    "00e04c": "Realtek",
    "525400": "QEMU/KVM",
    "00163e": "Xen",
    "080027": "VirtualBox",
    "0a0027": "VirtualBox",
    "50eb71": "TP-Link",
    "60a4b7": "TP-Link",
    "b0be76": "TP-Link",
    "c0c9e3": "TP-Link",
    "7c8334": "TP-Link",
    "30b5c2": "TP-Link",
    "981bb5": "ASUS",
    "2c56dc": "ASUS",
    "04d4c4": "ASUS",
    "00e018": "ASUS",
    "1c69a5": "LG Electronics",
    "00e091": "LG Electronics",
    "a0f459": "FN-LINK / IoT",
    "900f0c": "NETGEAR",
    "28c68e": "NETGEAR",
    "a021b7": "NETGEAR",
    "20e52a": "NETGEAR",
    "001e2a": "NETGEAR",
    "e046ee": "NETGEAR",
    "6c0b84": "Ubee / Cable modem",
    "00d0b7": "Espressif / IoT",
    "246f28": "Espressif",
    "a4cf12": "Espressif",
    "84cca8": "Espressif",
    "000c43": "Ralink/MediaTek",
    "00e0b8": "Allied Telesis",
    "fc4596": "Sonos",
    "5a5a5a": "Local admin",
}


def normalize_mac(mac: str) -> str:
    return (
        (mac or "")
        .lower()
        .replace("-", "")
        .replace(":", "")
        .replace(".", "")
        .strip()
    )


def vendor_from_mac(mac: str) -> str:
    hex6 = normalize_mac(mac)
    if len(hex6) < 6:
        return ""
    # Locally administered / random
    try:
        first_byte = int(hex6[0:2], 16)
        if first_byte & 0x02:
            # still try OUI first
            pass
    except ValueError:
        return ""
    key = hex6[:6]
    if key in OUI_VENDORS:
        return OUI_VENDORS[key]
    # VirtualBox / VMware special prefixes already covered
    return ""


def label_device(hostname: str, mac: str, fallback: str = "") -> str:
    vendor = vendor_from_mac(mac)
    host = (hostname or "").strip()
    if host and vendor and vendor.lower() not in host.lower():
        return f"{host} ({vendor})"
    if host:
        return host
    if vendor:
        return vendor
    return fallback or ""
