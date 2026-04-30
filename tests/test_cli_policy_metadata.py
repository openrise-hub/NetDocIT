import pathlib
import unittest


class TestCliPolicyMetadata(unittest.TestCase):
    def test_main_reports_policy_block_handling(self):
        source = (pathlib.Path(__file__).resolve().parent.parent / "src" / "main.py").read_text(encoding="utf-8")
        self.assertIn("scan_completion_state", source)
        self.assertIn("scan_completion_reason", source)


if __name__ == "__main__":
    unittest.main()