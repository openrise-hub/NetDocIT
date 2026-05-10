"""Smoke test: verifies the full discovery pipeline runs end-to-end.

Uses mocked PowerShell script output and database to exercise every
phase: env discovery → route parsing → ICMP sweep → TCP port scan →
WMI/SNMP enrichment → ingestion → reporting.
"""

import unittest
from unittest.mock import patch, MagicMock


class TestEndToEndSmoke(unittest.TestCase):
    def setUp(self):
        from src.backend.database import init_db
        init_db()

    @patch("src.backend.discovery.scan_appliances")
    @patch("src.backend.transports.icmp._raw_socket_available")
    @patch("src.backend.discovery.run_ps_script")
    def test_discover_all_runs_all_phases(self, mock_ps, mock_raw, mock_snmp):
        from src.backend.discovery import discover_all

        mock_raw.return_value = False
        mock_snmp.return_value = []

        def fake_ps(script, args=None, timeout_seconds=60):
            if "env_discovery" in script:
                return {
                    "interfaces": [
                        {"name": "Ethernet", "ipv4": "10.0.0.1", "mac": "aa-bb-cc-dd-ee-ff"}
                    ],
                    "routes": [
                        {"network": "10.0.0.0", "prefix_len": "24", "gateway": "10.0.0.1",
                         "interface": "Ethernet", "netmask": "255.255.255.0", "local_addr": "10.0.0.1"}
                    ],
                }
            if "ping_sweep" in script:
                return [
                    {"ip": "10.0.0.5", "mac": "11-22-33-44-55-66", "hostname": "10.0.0.5"},
                    {"ip": "10.0.0.10", "mac": "aa-aa-aa-aa-aa-aa", "hostname": "host-1"},
                ]
            if "host_enum" in script:
                return [
                    {"ip": "10.0.0.10", "hostname": "host-1", "os": "Windows 10", "vendor": "Dell"}
                ]
            return []

        mock_ps.side_effect = fake_ps

        result = discover_all(scan_profile="safe", script_timeout_seconds=30)
        self.assertIsInstance(result, dict)
        self.assertIn("interfaces", result)
        self.assertIn("routes", result)
        self.assertIn("subnets", result)
        self.assertIn("scan_data", result)
        self.assertIn("provenance", result)
        self.assertIn("health_report", result)
        self.assertIn("drift_report", result)
        self.assertIn("service_identity", result)
        self.assertEqual(result["scan_completion_state"], "completed")
        self.assertGreaterEqual(result["responsive_endpoint_count"], 1)
        self.assertGreaterEqual(result["scan_subnet_count"], 1)

    @patch("src.backend.scanner.subprocess.run")
    @patch("src.backend.discovery.scan_appliances")
    @patch("src.backend.transports.icmp._raw_socket_available")
    @patch("src.backend.discovery.run_ps_script")
    def test_ingest_live_data_persists_results(self, mock_ps, mock_raw, mock_snmp, mock_subproc):
        from src.backend.discovery import discover_all
        from src.backend.database import ingest_live_data, get_devices_sorted_by_ip

        mock_raw.return_value = False
        mock_snmp.return_value = []
        mock_subproc.return_value.returncode = 0

        def fake_ps(script, args=None, timeout_seconds=60):
            if "env_discovery" in script:
                return {
                    "interfaces": [
                        {"name": "Ethernet", "ipv4": "192.168.1.10", "mac": "cc-dd-ee-ff-00-11"}
                    ],
                    "routes": [
                        {"network": "192.168.1.0", "prefix_len": "24", "gateway": "192.168.1.1",
                         "interface": "Ethernet", "netmask": "255.255.255.0", "local_addr": "192.168.1.10"}
                    ],
                }
            if "ping_sweep" in script:
                return [
                    {"ip": "192.168.1.100", "mac": "ee-ee-ee-ee-ee-ee", "hostname": "device-1"}
                ]
            if "host_enum" in script:
                return [
                    {"ip": "192.168.1.100", "hostname": "device-1", "os": "Windows 11", "vendor": "Lenovo"}
                ]
            return []

        mock_ps.side_effect = fake_ps
        discovery = discover_all(scan_profile="balanced", script_timeout_seconds=30)
        ingestion = ingest_live_data(discovery)
        self.assertIsInstance(ingestion, dict)
        self.assertIsNotNone(ingestion.get("scan_run_id"))
        self.assertGreater(ingestion.get("observation_count", 0), 0)
        self.assertGreater(ingestion.get("resolved_host_count", 0), 0)

        devices = get_devices_sorted_by_ip()
        self.assertGreaterEqual(len(devices), 1)

    @patch("src.backend.scanner.subprocess.run")
    @patch("src.backend.discovery.scan_appliances")
    @patch("src.backend.transports.icmp._raw_socket_available")
    @patch("src.backend.discovery.run_ps_script")
    def test_preflight_scope_deny_blocks_scan(self, mock_ps, mock_raw, mock_snmp, mock_subproc):
        from src.backend.discovery import discover_all
        from unittest.mock import patch as _patch

        mock_raw.return_value = False
        mock_snmp.return_value = []
        mock_subproc.return_value.returncode = 0

        def fake_ps(script, args=None, timeout_seconds=60):
            if "env_discovery" in script:
                return {
                    "interfaces": [
                        {"name": "Ethernet", "ipv4": "10.0.0.1", "mac": "ff-ee-dd-cc-bb-aa"}
                    ],
                    "routes": [
                        {"network": "10.0.0.0", "prefix_len": "24", "gateway": "10.0.0.1",
                         "interface": "Ethernet", "netmask": "255.255.255.0", "local_addr": "10.0.0.1"}
                    ],
                }
            return []

        mock_ps.side_effect = fake_ps

        with _patch("src.backend.discovery.load_scope_policy") as mock_policy:
            from src.backend.safety_policy import ScopePolicy
            mock_policy.return_value = ScopePolicy(
                allow_subnets=frozenset(),
                deny_subnets=frozenset(["10.0.0.0/24"]),
                allow_hosts=frozenset(),
                deny_hosts=frozenset(),
                max_hosts=None,
                max_packets_per_second=None,
                max_concurrency=None,
            )
            result = discover_all(scan_profile="safe", script_timeout_seconds=30)
            self.assertEqual(result["scan_completion_state"], "blocked")

    @patch("src.backend.scanner.subprocess.run")
    @patch("src.backend.discovery.scan_appliances")
    @patch("src.backend.transports.icmp._raw_socket_available")
    @patch("src.backend.discovery.run_ps_script")
    def test_empty_network_handles_gracefully(self, mock_ps, mock_raw, mock_snmp, mock_subproc):
        from src.backend.discovery import discover_all

        mock_raw.return_value = False
        mock_snmp.return_value = []
        mock_subproc.return_value.returncode = 0

        def fake_ps(script, args=None, timeout_seconds=60):
            if "env_discovery" in script:
                return {
                    "interfaces": [],
                    "routes": [],
                }
            if "ping_sweep" in script:
                return []
            if "host_enum" in script:
                return []
            return []

        mock_ps.side_effect = fake_ps
        result = discover_all(scan_profile="safe", script_timeout_seconds=30)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["scan_completion_state"], "completed")
        self.assertEqual(result["responsive_endpoint_count"], 0)


if __name__ == "__main__":
    unittest.main()
