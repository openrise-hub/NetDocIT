import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


class _FakeApp:
    def __init__(self):
        self.state = "MENU"
        self.live_scan_devices = []
        self.last_discovery_summary = None
        self.devices = []

    def add_log(self, _msg):
        return None

    def apply_scan_event(self, _event, _payload=None):
        return None


class TestRunDiscoveryState(unittest.TestCase):
    @staticmethod
    def _load_main_module():
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")
        fake_topology = types.ModuleType("src.presentation.topology")

        class _FakeTopologyManager:
            def build_from_discovery(self, *_args, **_kwargs):
                return None

            def display_tui(self):
                return None

            def save_html_map(self, *_args, **_kwargs):
                return None

        fake_topology.TopologyManager = _FakeTopologyManager

        sys.modules.pop("src.main", None)
        with patch.dict(
            sys.modules,
            {
                "pysnmp": fake_pysnmp,
                "pysnmp.hlapi": fake_hlapi,
                "src.presentation.topology": fake_topology,
            },
        ):
            return importlib.import_module("src.main")

    def test_run_discovery_keeps_scanning_state_until_user_changes_it(self):
        app_main = self._load_main_module()
        app = _FakeApp()

        discovery_summary = {
            "subnets": [],
            "interfaces": [],
            "routes": [],
            "scan_data": [{"ip": "192.168.0.1"}],
            "host_data": [],
            "snmp_data": [],
            "scan_timeout_exceeded": False,
        }

        fake_markdown = MagicMock()
        with patch.object(app_main, "discover_all", return_value=discovery_summary), \
             patch.object(app_main, "ingest_live_data"), \
             patch.object(app_main, "get_devices_sorted_by_ip", return_value=[]), \
             patch.object(app_main, "get_device_counts_by_os", return_value={}), \
             patch.object(app_main, "TopologyManager") as mock_topology, \
             patch.object(app_main, "MarkdownGenerator", return_value=fake_markdown):

            mock_topology.return_value = MagicMock(
                build_from_discovery=MagicMock(),
                display_tui=MagicMock(),
                save_html_map=MagicMock(),
            )

            app_main.run_discovery(app=app, scan_profile="balanced", script_timeout_seconds=30)

        self.assertEqual(app.state, "SCANNING")
        self.assertEqual(app.last_discovery_summary, discovery_summary)


if __name__ == "__main__":
    unittest.main()
