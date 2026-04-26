import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoveryRunTiming(unittest.TestCase):
    def test_discover_all_exposes_timing_metadata(self):
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
                 patch.object(discovery, "run_ps_script", return_value=[]), \
                 patch.object(discovery.time, "monotonic", side_effect=[10.0, 12.75]):

                result = discovery.discover_all(scan_profile="balanced")

                self.assertEqual(result["run_started_monotonic"], 10.0)
                self.assertEqual(result["run_finished_monotonic"], 12.75)
                self.assertEqual(result["run_duration_seconds"], 2.75)


if __name__ == "__main__":
    unittest.main()
