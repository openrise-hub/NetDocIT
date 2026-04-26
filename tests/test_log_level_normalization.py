import os
import tempfile
import unittest

from src.backend import database


class TestLogLevelNormalization(unittest.TestCase):
    def test_add_log_entry_normalizes_level_to_uppercase(self):
        original_db_path = database.DB_PATH
        fd, test_db_path = tempfile.mkstemp(suffix="_netdocit_logs_test.sqlite")
        os.close(fd)

        try:
            database.DB_PATH = test_db_path
            database.init_db()
            database.add_log_entry("info", "test message", "Test")
            logs = database.get_logs(1)
            self.assertEqual(logs[0][1], "INFO")
        finally:
            database.DB_PATH = original_db_path


if __name__ == "__main__":
    unittest.main()
