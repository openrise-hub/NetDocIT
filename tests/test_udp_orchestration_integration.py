import importlib
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from src.backend import database


class TestUdpOrchestrationIntegration(unittest.TestCase):
    def setUp(self):
        self.original_db_path = database.DB_PATH
        fd, self.test_db_path = tempfile.mkstemp(suffix="_udp_orchestration_test.sqlite")
        os.close(fd)
        database.DB_PATH = self.test_db_path
        database.init_db()

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_probe_runner_results_persist_and_shape_service_identity(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")
            discovery = importlib.reload(discovery)

            def probe_impl(target, context):
                return [
                    {
                        "ip": target[0],
                        "target": target[0],
                        "port": target[1],
                        "service_hint": "snmp",
                        "sysName": "core-switch-1",
                        "sysDescr": "Cisco IOS Software",
                        "vendor": "Contoso",
                    },
                    {
                        "ip": target[0],
                        "target": target[0],
                        "port": target[1],
                        "service_hint": "snmp",
                        "sysName": "core-switch-2",
                        "sysDescr": "Cisco IOS Software",
                        "vendor": "Contoso",
                    }
                ]

            probe_results = discovery.run_scan_with_probes(
                targets=[("10.2.0.20", 161)],
                probe_impl=probe_impl,
                max_workers=1,
            )

            summary = {
                "scan_data": [],
                "host_data": [],
                "snmp_data": probe_results,
                "scan_completion_state": "completed",
            }
            summary["service_identity"] = discovery.build_service_identity_summary(summary)

            self.assertEqual(summary["service_identity"]["display_name"], "snmp")
            self.assertEqual(summary["service_identity"]["state"], "known")

            ingest_result = database.ingest_live_data(summary)
            self.assertEqual(ingest_result["observation_count"], 2)
            self.assertEqual(ingest_result["resolved_host_count"], 1)

            with database.get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT probe_type, ip, payload_json FROM probe_observations WHERE scan_run_id = ?",
                    (ingest_result["scan_run_id"],),
                )
                rows = cursor.fetchall()

            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0][0], "snmp")
            self.assertEqual(rows[0][1], "10.2.0.20")


if __name__ == "__main__":
    unittest.main()
