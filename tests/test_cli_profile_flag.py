import pathlib
import unittest


class TestCliProfileFlag(unittest.TestCase):
    def test_main_exposes_profile_flag_and_forwards_it(self):
        source = (pathlib.Path(__file__).resolve().parent.parent / "src" / "main.py").read_text(encoding="utf-8")
        self.assertIn("--profile", source)
        self.assertIn("scan_profile=args.profile", source)


if __name__ == "__main__":
    unittest.main()
