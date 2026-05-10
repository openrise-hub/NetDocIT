import unittest
from unittest.mock import patch, MagicMock

from src.backend.incremental import (
    is_stable,
    split_targets,
    get_cached_host_data,
    _get_known_ips,
)


class TestIsStable(unittest.TestCase):
    def test_seen_twice_no_flaps_is_stable(self):
        self.assertTrue(is_stable({"seen_count": 2, "flap_count": 0, "lifecycle_state": "new"}))

    def test_seen_once_is_not_stable(self):
        self.assertFalse(is_stable({"seen_count": 1, "flap_count": 0, "lifecycle_state": "new"}))

    def test_flapping_is_not_stable(self):
        self.assertFalse(is_stable({"seen_count": 5, "flap_count": 1, "lifecycle_state": "returned"}))

    def test_silent_is_not_stable(self):
        self.assertFalse(is_stable({"seen_count": 10, "flap_count": 0, "lifecycle_state": "silent"}))

    def test_missing_is_not_stable(self):
        self.assertFalse(is_stable({"seen_count": 5, "flap_count": 0, "lifecycle_state": "missing"}))

    def test_returned_no_flaps_is_stable(self):
        self.assertTrue(is_stable({"seen_count": 3, "flap_count": 0, "lifecycle_state": "returned"}))

    def test_seen_zero_is_not_stable(self):
        self.assertFalse(is_stable({"seen_count": 0, "flap_count": 0, "lifecycle_state": "new"}))


class TestSplitTargets(unittest.TestCase):
    @patch("src.backend.incremental._get_known_ips")
    def test_splits_stable_from_fresh(self, mock_known):
        mock_known.return_value = {
            "192.168.0.1": {"seen_count": 5, "flap_count": 0, "lifecycle_state": "new"},
            "192.168.0.10": {"seen_count": 1, "flap_count": 0, "lifecycle_state": "new"},
            "192.168.0.20": {"seen_count": 3, "flap_count": 2, "lifecycle_state": "returned"},
        }
        cached, fresh = split_targets(["192.168.0.1", "192.168.0.10", "192.168.0.20", "192.168.0.99"])
        self.assertEqual(cached, ["192.168.0.1"])
        self.assertEqual(sorted(fresh), ["192.168.0.10", "192.168.0.20", "192.168.0.99"])

    @patch("src.backend.incremental._get_known_ips")
    def test_empty_known_all_fresh(self, mock_known):
        mock_known.return_value = {}
        cached, fresh = split_targets(["10.0.0.1", "10.0.0.2"])
        self.assertEqual(cached, [])
        self.assertEqual(fresh, ["10.0.0.1", "10.0.0.2"])

    @patch("src.backend.incremental._get_known_ips")
    def test_all_stable_all_cached(self, mock_known):
        mock_known.return_value = {
            "10.0.0.1": {"seen_count": 4, "flap_count": 0, "lifecycle_state": "new"},
            "10.0.0.2": {"seen_count": 3, "flap_count": 0, "lifecycle_state": "returned"},
        }
        cached, fresh = split_targets(["10.0.0.1", "10.0.0.2"])
        self.assertEqual(cached, ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(fresh, [])

    @patch("src.backend.incremental._get_known_ips")
    def test_empty_input(self, mock_known):
        mock_known.return_value = {}
        cached, fresh = split_targets([])
        self.assertEqual(cached, [])
        self.assertEqual(fresh, [])


class TestGetCachedHostData(unittest.TestCase):
    def test_empty_ips_returns_empty_list(self):
        result = get_cached_host_data([])
        self.assertEqual(result, [])

    @patch("src.backend.incremental.get_db_connection")
    def test_returns_host_data_for_known_ips(self, mock_conn):
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("192.168.0.1", "AA:BB:CC:DD:EE:FF", "desktop-1", "Dell", "Dell Inc."),
        ]
        mock_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor

        result = get_cached_host_data(["192.168.0.1"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip"], "192.168.0.1")
        self.assertEqual(result[0]["hostname"], "desktop-1")
        self.assertIn("cached", result[0]["os"])

    @patch("src.backend.incremental.get_db_connection")
    def test_deduplicates_by_ip(self, mock_conn):
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("10.0.0.1", "11:22:33:44:55:66", "server-1", "HP", "HP"),
            ("10.0.0.1", "11:22:33:44:55:66", "server-1-new", "HP", "HP"),
        ]
        mock_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor

        result = get_cached_host_data(["10.0.0.1"])
        self.assertEqual(len(result), 1)


class TestGetKnownIps(unittest.TestCase):
    @patch("src.backend.incremental.get_db_connection")
    def test_returns_mapping_with_state(self, mock_conn):
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("192.168.0.1", "new", 3, 0, 42),
            ("192.168.0.10", "returned", 5, 1, 99),
        ]
        mock_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor

        result = _get_known_ips()
        self.assertIn("192.168.0.1", result)
        self.assertEqual(result["192.168.0.1"]["seen_count"], 3)
        self.assertEqual(result["192.168.0.1"]["lifecycle_state"], "new")

    @patch("src.backend.incremental.get_db_connection")
    def test_deduplicates_per_ip(self, mock_conn):
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("10.0.0.1", "new", 1, 0, 1),
            ("10.0.0.1", "returned", 5, 2, 1),
        ]
        mock_conn.return_value.__enter__.return_value.cursor.return_value = mock_cursor

        result = _get_known_ips()
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
