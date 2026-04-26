import os
import tempfile
import unittest

from src.backend import database


class TestDeviceIpSorting(unittest.TestCase):
    def test_get_devices_sorted_by_ip_uses_numeric_order(self):
        original_db_path = database.DB_PATH
        fd, test_db_path = tempfile.mkstemp(suffix="_netdocit_test.sqlite")
        os.close(fd)

        try:
            database.DB_PATH = test_db_path
            database.init_db()

            with database.get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany(
                    "INSERT INTO devices (ip, mac, hostname, os, vendor) VALUES (?, ?, ?, ?, ?)",
                    [
                        ("192.168.1.100", "AA-BB-CC-DD-EE-01", "host100", "Linux", "VendorA"),
                        ("192.168.1.2", "AA-BB-CC-DD-EE-02", "host2", "Linux", "VendorB"),
                        ("192.168.1.10", "AA-BB-CC-DD-EE-03", "host10", "Linux", "VendorC"),
                    ],
                )
                conn.commit()

            rows = database.get_devices_sorted_by_ip()
            ordered_ips = [row[0] for row in rows]
            self.assertEqual(ordered_ips, ["192.168.1.2", "192.168.1.10", "192.168.1.100"])
        finally:
            database.DB_PATH = original_db_path


if __name__ == "__main__":
    unittest.main()
