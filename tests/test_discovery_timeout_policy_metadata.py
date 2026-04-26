import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoveryTimeoutPolicyMetadata(unittest.TestCase):
    def test_discover_all_reports_timeout_policy_metadata_without_sanitization(self):
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
                 patch.object(discovery, "report_readiness", return_value={
                     "subnets": [],
                     "new": [],
                     "missing": [],
                     "priorities": {"high": [], "medium": [], "low": []},
                     "gateways": [],
                 }), \
                 patch.object(discovery, "run_ps_script", return_value=[]):

                result = discovery.discover_all(scan_profile="balanced", script_timeout_seconds=45)

                self.assertFalse(result["script_timeout_was_sanitized"])
                self.assertEqual(result["timeout_policy"]["default_seconds"], 60)
                self.assertEqual(result["timeout_policy"]["max_seconds"], 300)

    def test_discover_all_reports_timeout_policy_metadata_with_sanitization(self):
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
                 patch.object(discovery, "report_readiness", return_value={
                     "subnets": [],
                     "new": [],
                     "missing": [],
                     "priorities": {"high": [], "medium": [], "low": []},
                     "gateways": [],
                 }), \
                 patch.object(discovery, "run_ps_script", return_value=[]):

                result = discovery.discover_all(scan_profile="safe", script_timeout_seconds=0)

                self.assertTrue(result["script_timeout_was_sanitized"])
                self.assertEqual(result["script_timeout_source"], "fallback")


if __name__ == "__main__":
    unittest.main()
