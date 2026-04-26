import unittest
from unittest.mock import patch

from src.backend import vendor_lookup


class TestVendorLookupConnectionLifecycle(unittest.TestCase):
    @patch("src.backend.vendor_lookup.sqlite3.connect")
    @patch("src.backend.vendor_lookup.os.path.exists", return_value=True)
    def test_init_db_does_not_keep_global_open_connection(self, _exists, mock_connect):
        vendor_lookup._CONN = None
        vendor_lookup.init_db()
        self.assertIsNone(vendor_lookup._CONN)
        mock_connect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
