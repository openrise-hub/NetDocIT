import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoverySafetyProfiles(unittest.TestCase):
    def test_discovery_reports_safety_profile_metadata(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            with patch.object(discovery, "clear_interfaces"), \
                 patch.object(discovery, "clear_routes"), \
                 patch.object(discovery, "save_interface"), \
                 patch.object(discovery, "save_route"), \
                 patch.object(discovery, "get_active_interfaces", return_value=[]), \
                 patch.object(discovery, "get_routing_table", return_value=[]), \
                 patch.object(discovery, "get_subnets", return_value=[]), \
                 patch.object(discovery, "report_readiness", return_value={
                     "subnets": [],
                     "new": [],
                     "missing": [],
                     "priorities": {"high": [], "medium": [], "low": []},
                     "gateways": [],
                 }), \
                 patch.object(discovery, "run_ps_script", return_value=[]):

                result = discovery.discover_all(scan_profile="balanced")

                self.assertIn("safety_profile", result)
                self.assertEqual(result["safety_profile"]["name"], "balanced")
                self.assertEqual(result["safety_profile"]["default_scan_profile"], "balanced")

    def test_scan_defaults_remain_conservative(self):
        from src.backend.scanner import get_scan_profile

        profile = get_scan_profile(None)
        self.assertEqual(profile["script_timeout"], 180)


if __name__ == "__main__":
    unittest.main()