import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


class TestCliCommandSmoke(unittest.TestCase):
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

    @patch("src.backend.database.init_db")
    def test_scan_command_runs_discovery_mapping_and_reporting(self, _mock_init_db):
        app_main = self._load_main_module()

        with patch.object(app_main, "run_reporting") as mock_run_reporting, \
             patch.object(app_main, "run_mapping") as mock_run_mapping, \
             patch.object(app_main, "run_discovery") as mock_run_discovery, \
             patch.object(app_main, "DashboardApp") as mock_dashboard, \
             patch("rich.live.Live") as mock_live:

            fake_app = MagicMock()
            fake_app.render.return_value = "layout"
            fake_app.console = MagicMock()
            mock_dashboard.return_value = fake_app

            live_ctx = MagicMock()
            live_ctx.__enter__.return_value = MagicMock()
            live_ctx.__exit__.return_value = False
            mock_live.return_value = live_ctx

            mock_run_discovery.return_value = {"subnets": [], "interfaces": [], "routes": []}

            with patch("sys.argv", ["netdocit", "scan"]):
                app_main.main()

            mock_run_discovery.assert_called_once()
            mock_run_mapping.assert_called_once()
            mock_run_reporting.assert_called_once()

    @patch("src.backend.database.init_db")
    def test_map_command_invokes_mapping(self, _mock_init_db):
        app_main = self._load_main_module()
        with patch.object(app_main, "run_mapping") as mock_run_mapping:
            with patch("sys.argv", ["netdocit", "map"]):
                app_main.main()

            mock_run_mapping.assert_called_once_with()

    @patch("src.backend.database.init_db")
    def test_report_command_invokes_reporting(self, _mock_init_db):
        app_main = self._load_main_module()
        with patch.object(app_main, "run_reporting") as mock_run_reporting:
            with patch("sys.argv", ["netdocit", "report"]):
                app_main.main()

            mock_run_reporting.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
