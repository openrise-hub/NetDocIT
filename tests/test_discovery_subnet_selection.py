import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoverySubnetSelection(unittest.TestCase):
    def test_get_subnets_filters_reserved_and_broad_networks(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            routes = [
                {"network": "127.0.0.0", "prefix_len": "8"},
                {"network": "224.0.0.0", "prefix_len": "4"},
                {"network": "172.20.64.0", "prefix_len": "20"},
                {"network": "192.168.0.0", "prefix_len": "24"},
                {"network": "0.0.0.0", "prefix_len": "0"},
            ]

            self.assertEqual(discovery.get_subnets(routes), ["192.168.0.0/24"])

    def test_discover_all_uses_gateway_fallback_when_icmp_finds_none(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            routes = [
                {"network": "192.168.0.0", "prefix_len": "24", "gateway": "0.0.0.0", "interface": "Wi-Fi", "local_addr": "192.168.0.186"},
                {"network": "0.0.0.0", "prefix_len": "0", "gateway": "192.168.0.1", "interface": "Wi-Fi", "local_addr": "192.168.0.186"},
            ]

            with patch.object(discovery, "clear_interfaces"), \
                 patch.object(discovery, "clear_routes"), \
                 patch.object(discovery, "save_interface"), \
                 patch.object(discovery, "save_route"), \
                 patch.object(discovery, "get_active_interfaces", return_value=[]), \
                 patch.object(discovery, "get_routing_table", return_value=routes), \
                 patch.object(discovery, "report_readiness", return_value={
                     "subnets": [{"cidr": "192.168.0.0/24", "tag": "Wi-Fi"}],
                     "new": [],
                     "missing": [],
                     "priorities": {"high": [], "medium": [], "low": []},
                     "gateways": ["192.168.0.1"],
                 }), \
                 patch.object(discovery, "run_ps_script", side_effect=[[], []]), \
                 patch.object(discovery, "scan_appliances", return_value=[]), \
                 patch.object(discovery, "add_log_entry"), \
                 patch.object(discovery.time, "monotonic", side_effect=[10.0, 11.0, 12.0, 13.0, 14.0, 15.0]):

                result = discovery.discover_all(script_timeout_seconds=5)

                self.assertEqual(result["scan_completion_state"], "completed")
                self.assertEqual(result["responsive_endpoint_count"], 1)
                self.assertEqual(result["host_enum_target_count"], 1)
                self.assertEqual(result["scan_data"][0]["ip"], "192.168.0.1")


if __name__ == "__main__":
    unittest.main()