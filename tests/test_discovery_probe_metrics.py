import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoveryProbeMetrics(unittest.TestCase):
    def test_discover_all_emits_probe_metrics_for_all_probe_types(self):
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

                result = discovery.discover_all(script_timeout_seconds=10)

                self.assertIn("probe_metrics", result)
                for probe in ("icmp", "tcp", "snmp", "wmi"):
                    self.assertIn(probe, result["probe_metrics"])
                    self.assertIn("throughput_per_second", result["probe_metrics"][probe])


if __name__ == "__main__":
    unittest.main()
