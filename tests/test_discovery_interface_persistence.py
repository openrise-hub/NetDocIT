import unittest
import importlib
import sys
import types
from unittest.mock import patch


class TestDiscoveryInterfacePersistence(unittest.TestCase):
    def test_discover_all_persists_each_interface(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            with patch.object(discovery, "clear_interfaces") as mock_clear_interfaces, \
                 patch.object(discovery, "save_interface") as mock_save_interface, \
                  patch.object(discovery, "clear_routes") as mock_clear_routes, \
                  patch.object(discovery, "save_route") as mock_save_route, \
                 patch.object(discovery, "get_active_interfaces") as mock_get_active_interfaces, \
                 patch.object(discovery, "get_routing_table") as mock_get_routing_table, \
                 patch.object(discovery, "run_ps_script") as mock_run_ps_script, \
                 patch.object(discovery, "report_readiness") as mock_report_readiness:

                mock_get_active_interfaces.return_value = [
                    {
                        "name": "Ethernet0",
                        "description": "Up",
                        "ipv4": "192.168.1.10",
                        "mac": "AA-BB-CC-DD-EE-FF",
                    },
                    {
                        "name": "Wi-Fi",
                        "description": "Up",
                        "ipv4": "192.168.1.11",
                        "mac": "00-11-22-33-44-55",
                    },
                ]
                mock_get_routing_table.return_value = []
                mock_run_ps_script.return_value = []
                mock_report_readiness.return_value = {
                    "subnets": [],
                    "new": [],
                    "missing": [],
                    "priorities": {"high": [], "medium": [], "low": []},
                    "gateways": [],
                }

                discovery.discover_all()

                self.assertEqual(mock_save_interface.call_count, 2)


if __name__ == "__main__":
    unittest.main()
