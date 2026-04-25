import pathlib
import unittest


class TestCliDispatchBranches(unittest.TestCase):
    def test_only_one_if_not_cmd_list_guard_exists(self):
        source = (pathlib.Path(__file__).resolve().parent.parent / "src" / "main.py").read_text(encoding="utf-8")
        self.assertEqual(source.count("if not cmd_list:"), 1)


if __name__ == "__main__":
    unittest.main()
