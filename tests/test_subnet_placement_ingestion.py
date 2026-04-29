import os
import tempfile
import unittest

from src.backend import database


class TestSubnetPlacementIngestion(unittest.TestCase):
    def setUp(self):
        self.original_db_path = database.DB_PATH
        fd, self.test_db_path = tempfile.mkstemp(suffix="_subnet_placement_ingest.sqlite")
        os.close(fd)
        database.DB_PATH = self.test_db_path
        database.init_db()

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_ingest_live_data_persists_primary_and_alternate_placements(self):
        summary = {
            'scan_run_id': 'scan-1',
            'interfaces': [{'name': 'eth0', 'ipv4': '10.0.0.1'}],
            'routes': [{'network': '10.0.0.0', 'prefix_len': '24', 'interface': 'eth0', 'local_addr': '10.0.0.1'}],
            'subnets': [{'cidr': '10.0.0.0/24', 'tag': 'Office'}, {'cidr': '10.0.0.0/25', 'tag': 'Office-Alt'}],
            'scan_data': [{'ip': '10.0.0.10', 'mac': 'AA-BB-CC-DD-EE-FF'}],
            'host_data': [{'ip': '10.0.0.10', 'hostname': 'srv-01', 'vendor': 'Contoso'}],
            'snmp_data': [],
            'scan_completion_state': 'completed',
        }

        result = database.ingest_live_data(summary)

        with database.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM asset_subnet_placements')
            placement_count = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM asset_subnet_candidates')
            candidate_count = cursor.fetchone()[0]

        self.assertTrue(result['resolved_state_updated'])
        self.assertGreaterEqual(placement_count, 1)
        self.assertGreaterEqual(candidate_count, 1)


if __name__ == '__main__':
    unittest.main()
