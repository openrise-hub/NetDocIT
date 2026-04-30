import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoveryCredentialAudit(unittest.TestCase):
    def test_discover_all_exposes_credential_audit_metadata(self):
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
                 patch.object(discovery, "resolve_snmp_credentials", return_value=(
                     ["public"],
                     {
                         "source": "external_file",
                         "loaded": True,
                         "credential_count": 1,
                         "load_error": None,
                         "rotation_due": "2026-06-01T00:00:00",
                         "expires_at": None,
                     },
                 )):

                result = discovery.discover_all(scan_profile="safe")

                self.assertIn("credential_audit", result)
                self.assertEqual(result["credential_audit"]["source"], "external_file")
                self.assertEqual(result["credential_audit"]["credential_count"], 1)
                self.assertIsNone(result["credential_audit"]["load_error"])

    def test_discover_all_logs_warning_on_credential_load_error(self):
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
                 patch.object(discovery, "add_log_entry") as add_log_entry_mock, \
                 patch.object(discovery, "resolve_snmp_credentials", return_value=(
                     [],
                     {
                         "source": "external_file",
                         "loaded": False,
                         "credential_count": 0,
                         "load_error": "secrets_file_required_in_production",
                         "rotation_due": None,
                         "expires_at": None,
                     },
                 )):

                result = discovery.discover_all(scan_profile="safe")

                self.assertEqual(
                    result["credential_audit"]["load_error"],
                    "secrets_file_required_in_production",
                )
                warning_calls = [
                    call for call in add_log_entry_mock.call_args_list
                    if call.args and call.args[0] == "WARNING"
                ]
                self.assertTrue(
                    any("SNMP credential loading issue" in call.args[1] for call in warning_calls)
                )


if __name__ == "__main__":
    unittest.main()
