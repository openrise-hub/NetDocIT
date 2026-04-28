import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoveryAbortSignal(unittest.TestCase):
    def test_discover_all_aborts_with_sentinel_reason_code(self):
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
                 patch.object(discovery, "get_subnets", return_value=["10.0.0.0/24"]), \
                 patch.object(discovery, "report_readiness", return_value={
                     "subnets": [],
                     "new": [],
                     "missing": [],
                     "priorities": {"high": [], "medium": [], "low": []},
                     "gateways": [],
                 }), \
                 patch.object(discovery, "run_ps_script", return_value=[]) as run_ps_script:

                result = discovery.discover_all(abort_signal=lambda: True)

                self.assertEqual(result["scan_completion_state"], "aborted")
                self.assertEqual(result["scan_completion_reason"], "sentinel_triggered")
                self.assertEqual(result["scan_data"], [])
                run_ps_script.assert_not_called()


if __name__ == "__main__":
    unittest.main()
