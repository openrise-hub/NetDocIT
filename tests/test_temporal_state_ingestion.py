import os
import tempfile
import unittest

from src.backend import database


class TestTemporalStateIngestion(unittest.TestCase):
    def setUp(self):
        self.original_db_path = database.DB_PATH
        fd, self.test_db_path = tempfile.mkstemp(suffix="_temporal_state_ingest.sqlite")
        os.close(fd)
        database.DB_PATH = self.test_db_path
        database.init_db()

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_ingest_live_data_updates_temporal_state(self):
        summary = {
            "scan_run_id": "scan-1",
            "scan_data": [{"ip": "10.0.0.10", "mac": "AA-BB-CC-DD-EE-FF"}],
            "host_data": [{"ip": "10.0.0.10", "hostname": "srv-01", "vendor": "Contoso"}],
            "snmp_data": [{"ip": "10.0.0.10", "sysName": "srv-01", "sysDescr": "Contoso Router", "vendor": "Contoso"}],
            "scan_completion_state": "completed",
        }

        result = database.ingest_live_data(summary)

        with database.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT seen_count, lifecycle_state FROM asset_temporal_state")
            row = cursor.fetchone()

        self.assertTrue(result["resolved_state_updated"])
        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], "new")


if __name__ == "__main__":
    unittest.main()
