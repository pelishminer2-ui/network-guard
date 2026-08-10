#!/usr/bin/env python3
"""Basic unit tests for Network Guard helpers."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ng_oui import vendor_from_mac, label_device  # noqa: E402
from ng_profiles import is_port_expected, filter_unexpected_ports  # noqa: E402
from ng_history import connect, upsert_host, new_ports_vs_baseline, save_baseline  # noqa: E402
import network_guard as ng  # noqa: E402


class OUITests(unittest.TestCase):
    def test_roku_mac(self):
        self.assertEqual(vendor_from_mac("7c:67:ab:0c:b3:94"), "Roku")

    def test_label(self):
        self.assertIn("Roku", label_device("", "7c:67:ab:00:00:01"))


class ProfileTests(unittest.TestCase):
    def test_roku_8888_expected(self):
        self.assertTrue(is_port_expected("ROKU", 8888))

    def test_filter(self):
        unexpected = filter_unexpected_ports("ROKU", [8888, 4444])
        self.assertEqual(unexpected, [4444])


class PortGlossaryTests(unittest.TestCase):
    def test_describe(self):
        self.assertIn("RDP", ng.describe_port(3389))
        self.assertIn("Roku", ng.describe_port(8060))


class HistoryTests(unittest.TestCase):
    def test_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            db = str(Path(td) / "t.db")
            upsert_host("192.168.1.102", mac="7c:67:ab:00:00:01", hostname="ROKU", open_ports=[8888], db_name=db)
            save_baseline([{"ip": "192.168.1.102", "open_ports": [8888]}], db_name=db)
            self.assertEqual(new_ports_vs_baseline("192.168.1.102", [8888, 4444], db_name=db), [4444])
            self.assertEqual(new_ports_vs_baseline("192.168.1.102", [8888], db_name=db), [])


class WorsenedTests(unittest.TestCase):
    def test_worsened(self):
        prev = {"suspicious_ports": [8080], "reasons": ["a"], "remote_port": 8080, "process_name": "x"}
        cur = {"suspicious_ports": [8080, 4444], "reasons": ["a", "b"], "remote_port": 4444, "process_name": "x"}
        bad, changes = ng.traffic_worsened(prev, cur)
        self.assertTrue(bad)
        self.assertTrue(any("4444" in c for c in changes))


class BannerTests(unittest.TestCase):
    def test_hint_keys(self):
        from ng_banner import grab_banner

        # Non-routable; should fail soft with empty-ish dict keys present
        out = grab_banner("203.0.113.1", 65530, timeout=0.2)
        self.assertIn("hint", out)
        self.assertIn("banner", out)


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        from ng_config import load_config

        cfg = load_config()
        self.assertIn("dashboard_port", cfg)
        self.assertTrue(isinstance(cfg.get("quick_ports"), list))


if __name__ == "__main__":
    unittest.main()
