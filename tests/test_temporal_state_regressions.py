import os
import tempfile
import unittest

from src.backend import database


class TestTemporalStateRegressions(unittest.TestCase):
    def setUp(self):
        self.original_db_path = database.DB_PATH
        fd, self.test_db_path = tempfile.mkstemp(suffix="_temporal_state_regression.sqlite")
        os.close(fd)
        database.DB_PATH = self.test_db_path
        database.init_db()

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_aborted_scan_does_not_advance_temporal_state(self):
        completed = {
            "scan_run_id": "scan-1",
            "scan_data": [{"ip": "10.0.0.10", "mac": "AA-BB-CC-DD-EE-FF"}],
            "host_data": [{"ip": "10.0.0.10", "hostname": "srv-01"}],
            "snmp_data": [],
            "scan_completion_state": "completed",
        }
        aborted = {
            "scan_run_id": "scan-2",
            "scan_data": [],
            "host_data": [],
            "snmp_data": [],
            "scan_completion_state": "aborted",
        }

        database.ingest_live_data(completed)
        database.ingest_live_data(aborted)

        with database.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT seen_count, lifecycle_state FROM asset_temporal_state")
            row = cursor.fetchone()

        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], "new")


if __name__ == "__main__":
    unittest.main()
