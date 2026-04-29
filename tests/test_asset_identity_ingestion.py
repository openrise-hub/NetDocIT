import os
import tempfile
import unittest

from src.backend import database


class TestAssetIdentityIngestion(unittest.TestCase):
    def setUp(self):
        self.original_db_path = database.DB_PATH
        fd, self.test_db_path = tempfile.mkstemp(suffix="_asset_identity_ingest.sqlite")
        os.close(fd)
        database.DB_PATH = self.test_db_path
        database.init_db()

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_repeated_sightings_merge_into_one_canonical_asset(self):
        first_summary = {
            "scan_data": [{"ip": "10.0.0.10", "mac": "AA-BB-CC-DD-EE-FF"}],
            "host_data": [{"ip": "10.0.0.10", "hostname": "srv-01", "vendor": "Contoso"}],
            "snmp_data": [{"ip": "10.0.0.10", "sysName": "srv-01", "sysDescr": "Contoso Router", "vendor": "Contoso"}],
            "scan_completion_state": "completed",
        }
        second_summary = {
            "scan_data": [{"ip": "10.0.0.21", "mac": "11-22-33-44-55-66"}],
            "host_data": [{"ip": "10.0.0.21", "hostname": "srv-01", "vendor": "Contoso"}],
            "snmp_data": [{"ip": "10.0.0.21", "sysName": "srv-01", "sysDescr": "Contoso Router", "vendor": "Contoso"}],
            "scan_completion_state": "completed",
        }

        database.ingest_live_data(first_summary)
        database.ingest_live_data(second_summary)

        with database.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM canonical_assets")
            canonical_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM asset_aliases")
            alias_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM devices")
            device_count = cursor.fetchone()[0]

        self.assertEqual(canonical_count, 1)
        self.assertGreaterEqual(alias_count, 2)
        self.assertEqual(device_count, 1)


if __name__ == "__main__":
    unittest.main()
