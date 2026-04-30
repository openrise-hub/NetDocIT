import importlib
import sys
import types
import unittest
from unittest.mock import patch

from src.backend.safety_policy import ScopePolicy


class TestDiscoveryScopePolicy(unittest.TestCase):
    def test_discovery_fails_closed_before_ping_sweep(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            policy = ScopePolicy(
                allow_subnets=frozenset({"10.0.0.0/24"}),
                deny_subnets=frozenset({"10.0.1.0/24"}),
                allow_hosts=frozenset(),
                deny_hosts=frozenset(),
                max_hosts=2,
                max_packets_per_second=100,
                max_concurrency=4,
            )

            with patch.object(discovery, "load_scope_policy", return_value=policy), \
                 patch.object(discovery, "clear_interfaces"), \
                 patch.object(discovery, "clear_routes"), \
                 patch.object(discovery, "save_interface"), \
                 patch.object(discovery, "save_route"), \
                 patch.object(discovery, "get_active_interfaces", return_value=[]), \
                 patch.object(discovery, "get_routing_table", return_value=[]), \
                 patch.object(discovery, "get_subnets", return_value=["10.0.1.0/24"]), \
                 patch.object(discovery, "report_readiness") as report_readiness, \
                 patch.object(discovery, "run_ps_script") as run_ps_script:

                result = discovery.discover_all(scan_profile="safe", script_timeout_seconds=None)

                self.assertEqual(result["scan_completion_state"], "blocked")
                self.assertEqual(result["scan_completion_reason"], "policy_denied_scope")
                self.assertFalse(result["scope_policy_decision"]["allowed"])
                self.assertEqual(result["scope_policy"]["deny_subnets"], ["10.0.1.0/24"])
                report_readiness.assert_not_called()
                run_ps_script.assert_not_called()

    def test_discovery_includes_policy_metadata_on_allowed_run(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            policy = ScopePolicy(
                allow_subnets=frozenset(),
                deny_subnets=frozenset(),
                allow_hosts=frozenset(),
                deny_hosts=frozenset(),
                max_hosts=50,
                max_packets_per_second=120,
                max_concurrency=6,
            )

            with patch.object(discovery, "load_scope_policy", return_value=policy), \
                 patch.object(discovery, "clear_interfaces"), \
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

                result = discovery.discover_all(scan_profile="safe", script_timeout_seconds=None)

                self.assertEqual(result["scan_completion_state"], "completed")
                self.assertEqual(result["scope_policy"]["max_packets_per_second"], 120)
                self.assertTrue(result["scope_policy_decision"]["allowed"])
                self.assertEqual(result["scope_policy_decision"]["effective_limits"]["max_concurrency"], 6)


if __name__ == "__main__":
    unittest.main()