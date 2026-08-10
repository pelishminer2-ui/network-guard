#!/usr/bin/env python3
"""Notifications for Network Guard."""

from __future__ import annotations

import platform
import subprocess


def _xml_esc(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def notify(title: str, message: str) -> None:
    """Best-effort desktop notification (Windows toast / Linux notify-send)."""
    system = platform.system().lower()
    if system == "windows":
        script = f"""
$ErrorActionPreference='SilentlyContinue'
[void][Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
$t = @'
<toast><visual><binding template="ToastGeneric"><text>{_xml_esc(title)}</text><text>{_xml_esc(message)}</text></binding></visual></toast>
'@
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($t)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('NetworkGuard').Show($toast)
"""
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return
        except Exception:
            try:
                subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        f"New-BurntToastNotification -Text '{title}','{message}'",
                    ],
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                pass
            return
    try:
        subprocess.run(["notify-send", title, message], capture_output=True, timeout=5)
    except Exception:
        pass
