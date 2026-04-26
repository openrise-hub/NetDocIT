import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoveryProfileTimeout(unittest.TestCase):
    def test_discover_all_uses_profile_timeout_when_no_override(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            with patch.object(discovery, "clear_interfaces"), \
                 patch.object(discovery, "clear_routes"), \
                 patch.object(discovery, "save_interface"), \
                 patch.object(discovery, "save_route"), \
                 patch.object(discovery, "get_active_interfaces", return_value=[]) as get_active_interfaces, \
                 patch.object(discovery, "get_routing_table", return_value=[]), \
                 patch.object(discovery, "report_readiness", return_value={
                     "subnets": [],
                     "new": [],
                     "missing": [],
                     "priorities": {"high": [], "medium": [], "low": []},
                     "gateways": [],
                 }), \
                 patch.object(discovery, "run_ps_script", return_value=[]):

                discovery.discover_all(scan_profile="safe", script_timeout_seconds=None)

                get_active_interfaces.assert_called_once_with(timeout_seconds=90)


if __name__ == "__main__":
    unittest.main()
