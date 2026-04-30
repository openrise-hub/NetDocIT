import importlib
import sys
import types
import unittest
from unittest.mock import patch


class DummyScheduler:
    def __init__(self, *args, **kwargs):
        pass

    def run(self, tasks):
        return {
            "metrics": {
                "icmp": {
                    "submitted": 10,
                    "completed": 10,
                    "timeouts": 8,
                    "backpressure_events": 5,
                    "timeout_ratio": 0.8,
                }
            },
            "results": {"icmp": [[{"ip": "10.0.0.5"}]]},
        }


class TestDiscoverySafetyAbort(unittest.TestCase):
    def test_discovery_aborts_on_safety_profile_signals(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            with patch.object(discovery, "AdaptiveProbeScheduler", new=DummyScheduler), \
                 patch.object(discovery, "clear_interfaces"), \
                 patch.object(discovery, "clear_routes"), \
                 patch.object(discovery, "save_interface"), \
                 patch.object(discovery, "save_route"), \
                 patch.object(discovery, "get_active_interfaces", return_value=[]), \
                 patch.object(discovery, "get_routing_table", return_value=[]), \
                 patch.object(discovery, "get_subnets", return_value=["10.0.0.0/24"]), \
                 patch.object(discovery, "run_ps_script", return_value=[]):

                result = discovery.discover_all(scan_profile="safe", script_timeout_seconds=None)

                self.assertIn(result["scan_completion_state"], {"aborted", "budget_exceeded"})
                self.assertEqual(result["scan_completion_reason"], "safety_profile_abort")

    def test_discovery_aborts_on_distress_metrics(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        distress_run = {
            "results": {"icmp": [[{"ip": "10.0.0.1"}]], "tcp": [], "snmp": [], "wmi": []},
            "metrics": {
                "icmp": {"submitted": 1, "completed": 1, "timeouts": 1, "backpressure_events": 1, "max_in_flight": 1, "throughput_per_second": 1.0, "timeout_ratio": 1.0, "avg_latency_seconds": 0.5, "latency_p95_seconds": 0.5, "recommended_timeout_seconds": 1.0, "retry_attempts": 0},
                "tcp": {"submitted": 0, "completed": 0, "timeouts": 0, "backpressure_events": 0, "max_in_flight": 0, "throughput_per_second": 0.0, "timeout_ratio": 0.0, "avg_latency_seconds": 0.0, "latency_p95_seconds": 0.0, "recommended_timeout_seconds": 0.0, "retry_attempts": 0},
                "snmp": {"submitted": 0, "completed": 0, "timeouts": 0, "backpressure_events": 0, "max_in_flight": 0, "throughput_per_second": 0.0, "timeout_ratio": 0.0, "avg_latency_seconds": 0.0, "latency_p95_seconds": 0.0, "recommended_timeout_seconds": 0.0, "retry_attempts": 0},
                "wmi": {"submitted": 0, "completed": 0, "timeouts": 0, "backpressure_events": 0, "max_in_flight": 0, "throughput_per_second": 0.0, "timeout_ratio": 0.0, "avg_latency_seconds": 0.0, "latency_p95_seconds": 0.0, "recommended_timeout_seconds": 0.0, "retry_attempts": 0},
            },
            "dispatch_order": [("icmp", "10.0.0.0/24", "host-1")],
            "soft_limits": {"icmp": 32, "tcp": 16, "snmp": 12, "wmi": 8},
            "max_global_in_flight": 1,
            "cpu_backpressure_events": 0,
        }

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            class DistressScheduler:
                def __init__(self, *args, **kwargs):
                    pass

                def run(self, tasks):
                    return distress_run

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
                 patch.object(discovery, "run_ps_script", return_value=[]), \
                 patch.object(discovery, "AdaptiveProbeScheduler", new=DistressScheduler):

                result = discovery.discover_all(scan_profile="balanced")

                self.assertEqual(result["scan_completion_state"], "aborted")
                self.assertEqual(result["scan_completion_reason"], "safety_profile_abort")
                self.assertEqual(result["safety_profile"]["name"], "balanced")


if __name__ == "__main__":
    unittest.main()