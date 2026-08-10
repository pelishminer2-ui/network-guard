#!/usr/bin/env python3
"""Network Guard shared config loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.yaml"
CONFIG_EXAMPLE = SCRIPT_DIR / "config.example.yaml"

DEFAULTS: Dict[str, Any] = {
    "subnet": None,
    "lan_workers": 48,
    "lan_port_timeout": 0.35,
    "quiet_watch_default": True,
    "dashboard_port": 8765,
    "temp_block_minutes": 60,
    "baseline_enabled": True,
    "notify_on_new_device": False,
    "history_db": "history.db",
    "watchlist": [],
    "reputation_blocklist": "reputation_blocklist.txt",
    "quick_ports": [22, 23, 80, 443, 445, 3389, 8080, 8443, 8888, 8060],
}


def _parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Tiny YAML subset parser (key: value, lists with - item). No PyYAML required."""
    data: Dict[str, Any] = {}
    current_list = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.strip().startswith("- ") and current_list is not None:
            item = line.strip()[2:].strip().strip('"').strip("'")
            if item.isdigit():
                data[current_list].append(int(item))
            else:
                data[current_list].append(item)
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        current_list = None
        if val == "" or val == "[]":
            data[key] = []
            current_list = key
            continue
        if val.lower() in ("true", "yes", "on"):
            data[key] = True
        elif val.lower() in ("false", "no", "off"):
            data[key] = False
        elif val.lower() in ("null", "none", "~"):
            data[key] = None
        elif val.isdigit():
            data[key] = int(val)
        else:
            try:
                data[key] = float(val)
            except ValueError:
                data[key] = val.strip('"').strip("'")
    return data


def ensure_example_config() -> None:
    if CONFIG_EXAMPLE.exists():
        return
    CONFIG_EXAMPLE.write_text(
        """# Network Guard configuration (copy to config.yaml to customize)
# Author: Pilisi W — 2026

subnet: null
lan_workers: 48
lan_port_timeout: 0.35
quiet_watch_default: true
dashboard_port: 8765
temp_block_minutes: 60
baseline_enabled: true
notify_on_new_device: true
history_db: history.db
reputation_blocklist: reputation_blocklist.txt

watchlist:
  - 192.168.1.102
  - 192.168.1.1

quick_ports:
  - 22
  - 23
  - 80
  - 443
  - 445
  - 3389
  - 8060
  - 8080
  - 8443
  - 8888
""",
        encoding="utf-8",
    )


def load_config() -> Dict[str, Any]:
    ensure_example_config()
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        try:
            parsed = _parse_simple_yaml(CONFIG_PATH.read_text(encoding="utf-8"))
            cfg.update(parsed)
        except OSError:
            pass
    # Also allow JSON override
    json_path = SCRIPT_DIR / "config.json"
    if json_path.exists():
        try:
            cfg.update(json.loads(json_path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
    return cfg
