import os
import tempfile
import unittest

from src.backend import database


class TestTemporalStateStorage(unittest.TestCase):
    def setUp(self):
        self.original_db_path = database.DB_PATH
        fd, self.test_db_path = tempfile.mkstemp(suffix="_temporal_state.sqlite")
        os.close(fd)
        database.DB_PATH = self.test_db_path
        database.init_db()

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_temporal_tables_exist(self):
        with database.get_db_connection() as conn:
            cursor = conn.cursor()
            for table_name in ("asset_temporal_state", "asset_lifecycle_events"):
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table_name,),
                )
                self.assertIsNotNone(cursor.fetchone())


if __name__ == "__main__":
    unittest.main()
