import os
import tempfile
import unittest

from src.backend import database


class TestStoragePipeline(unittest.TestCase):
    def setUp(self):
        self.original_db_path = database.DB_PATH
        fd, self.test_db_path = tempfile.mkstemp(suffix="_netdocit_storage_test.sqlite")
        os.close(fd)
        database.DB_PATH = self.test_db_path
        database.init_db()

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_ingest_live_data_persists_raw_and_resolved_views(self):
        summary = {
            "scan_data": [{"ip": "10.0.0.10", "mac": "AA-BB-CC-DD-EE-FF"}],
            "host_data": [{"ip": "10.0.0.10", "hostname": "srv-01", "os": "Windows 11"}],
            "snmp_data": [{"ip": "10.0.0.10", "sysDescr": "SwitchOS", "vendor": "Contoso"}],
            "scan_completion_state": "completed",
        }

        database.ingest_live_data(summary)

        with database.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM probe_observations")
            observation_count = cursor.fetchone()[0]
            cursor.execute("SELECT ip, hostname, os, vendor FROM devices")
            rows = cursor.fetchall()

        self.assertEqual(observation_count, 3)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "10.0.0.10")
        self.assertEqual(rows[0][1], "srv-01")
        self.assertEqual(rows[0][3], "Contoso")

    def test_ingest_live_data_keeps_resolved_hosts_on_aborted_scan(self):
        database.ingest_live_data(
            {
                "scan_data": [{"ip": "10.0.0.20", "mac": "00-11-22-33-44-55"}],
                "host_data": [{"ip": "10.0.0.20", "hostname": "baseline"}],
                "snmp_data": [],
                "scan_completion_state": "completed",
            }
        )

        database.ingest_live_data(
            {
                "scan_data": [{"ip": "10.0.0.99", "mac": "AA-00-00-00-00-99"}],
                "host_data": [{"ip": "10.0.0.99", "hostname": "interrupted"}],
                "snmp_data": [],
                "scan_completion_state": "aborted",
            }
        )

        devices = database.get_devices_sorted_by_ip()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0][0], "10.0.0.20")

    def test_persist_probe_observations_batches_large_input(self):
        summary = {
            "scan_data": [
                {"ip": f"10.1.0.{i % 254 + 1}", "mac": f"AA-BB-CC-00-00-{i % 100:02d}"}
                for i in range(350)
            ],
            "host_data": [],
            "snmp_data": [],
        }

        scan_run_id, inserted = database.persist_probe_observations(summary, batch_size=50)

        with database.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM probe_observations WHERE scan_run_id = ?", (scan_run_id,))
            count = cursor.fetchone()[0]

        self.assertEqual(inserted, 350)
        self.assertEqual(count, 350)

    def test_persist_probe_observations_includes_probe_evidence_rows(self):
        summary = {
            "probe_observations": [
                {
                    "target": "10.2.0.53",
                    "port": 53,
                    "service_hint": "dns",
                    "normalized_banner": "bind 9.18",
                    "service_state": "known",
                }
            ],
            "scan_data": [],
            "host_data": [],
            "snmp_data": [],
        }

        scan_run_id, inserted = database.persist_probe_observations(summary)

        with database.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT probe_type, ip, payload_json FROM probe_observations WHERE scan_run_id = ?",
                (scan_run_id,),
            )
            rows = cursor.fetchall()

        self.assertEqual(inserted, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "dns")
        self.assertEqual(rows[0][1], "10.2.0.53")


if __name__ == "__main__":
    unittest.main()
