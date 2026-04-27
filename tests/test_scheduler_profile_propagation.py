import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


class TestSchedulerProfilePropagation(unittest.TestCase):
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
    def test_install_scheduler_includes_profile_in_task_command(self, _mock_init_db):
        app_main = self._load_main_module()

        with patch.object(app_main, "is_admin", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock()

            result = app_main.install_scheduler("08:30", profile="safe")

            self.assertTrue(result)
            args = mock_run.call_args.args[0]
            joined = " ".join(args)
            self.assertIn("--profile safe", joined)

    @patch("src.backend.database.init_db")
    def test_schedule_command_forwards_profile_to_scheduler(self, _mock_init_db):
        app_main = self._load_main_module()

        with patch.object(app_main, "install_scheduler", return_value=True) as mock_install:
            with patch("sys.argv", ["netdocit", "schedule", "09:15", "--profile", "aggressive"]):
                app_main.main()

            mock_install.assert_called_once_with("09:15", profile="aggressive")


if __name__ == "__main__":
    unittest.main()
