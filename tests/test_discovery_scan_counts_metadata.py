import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoveryScanCountsMetadata(unittest.TestCase):
    def test_discover_all_exposes_scan_counts(self):
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
                 patch.object(discovery, "get_subnets", return_value=["10.0.0.0/24", "10.0.1.0/24"]), \
                 patch.object(discovery, "report_readiness", return_value={
                     "subnets": [],
                     "new": [],
                     "missing": [],
                     "priorities": {"high": [], "medium": [], "low": []},
                     "gateways": [],
                 }), \
                 patch.object(discovery, "run_ps_script", return_value=[{"ip": "10.0.0.10"}, {"ip": "10.0.1.11"}]):

                result = discovery.discover_all()

                self.assertEqual(result["scan_subnet_count"], 2)
                self.assertEqual(result["responsive_endpoint_count"], 2)


if __name__ == "__main__":
    unittest.main()
