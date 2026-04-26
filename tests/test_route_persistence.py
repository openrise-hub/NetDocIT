import os
import tempfile
import unittest

from src.backend import database


class TestRoutePersistence(unittest.TestCase):
    def test_save_and_get_routes_roundtrip(self):
        original_db_path = database.DB_PATH
        fd, test_db_path = tempfile.mkstemp(suffix="_netdocit_routes_test.sqlite")
        os.close(fd)

        try:
            database.DB_PATH = test_db_path
            database.init_db()

            database.save_route(
                {
                    "network": "192.168.1.0",
                    "netmask": "255.255.255.0",
                    "prefix_len": "24",
                    "gateway": "192.168.1.1",
                    "interface": "Ethernet0",
                    "local_addr": "192.168.1.10",
                }
            )

            routes = database.get_all_routes()
            self.assertEqual(len(routes), 1)
            self.assertEqual(routes[0]["network"], "192.168.1.0")
            self.assertEqual(routes[0]["interface"], "Ethernet0")
        finally:
            database.DB_PATH = original_db_path


if __name__ == "__main__":
    unittest.main()
