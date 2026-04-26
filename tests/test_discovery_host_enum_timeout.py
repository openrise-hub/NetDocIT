import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoveryHostEnumTimeout(unittest.TestCase):
    def test_discover_all_forwards_timeout_to_host_enum(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            def _run_ps_side_effect(script_name, args=None, timeout_seconds=60):
                if script_name == "ping_sweep.ps1":
                    return [{"ip": "10.0.0.10"}]
                if script_name == "host_enum.ps1":
                    return []
                return []

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
                 patch.object(discovery, "scan_appliances", return_value=[]), \
                 patch.object(discovery, "get_subnets", return_value=["10.0.0.0/24"]), \
                 patch.object(discovery, "run_ps_script", side_effect=_run_ps_side_effect) as run_ps_script:

                discovery.discover_all(script_timeout_seconds=45)

                run_ps_script.assert_any_call("host_enum.ps1", args=["10.0.0.10"], timeout_seconds=45)


if __name__ == "__main__":
    unittest.main()
