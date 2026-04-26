import unittest
from unittest.mock import patch

from src.backend import database


class _FakeConnection:
    def __init__(self):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def close(self):
        self.closed = True


class TestDatabaseConnectionLifecycle(unittest.TestCase):
    @patch("src.backend.database.os.makedirs")
    @patch("src.backend.database.sqlite3.connect")
    def test_get_db_connection_context_closes_connection(self, mock_connect, _makedirs):
        fake_conn = _FakeConnection()
        mock_connect.return_value = fake_conn

        with database.get_db_connection() as _conn:
            pass

        self.assertTrue(fake_conn.closed)


if __name__ == "__main__":
    unittest.main()
