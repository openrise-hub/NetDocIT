import pathlib
import unittest


class TestMainCrossPlatformImportGuard(unittest.TestCase):
    def test_main_guards_msvcrt_import_for_non_windows(self):
        source = (pathlib.Path(__file__).resolve().parent.parent / "src" / "main.py").read_text(encoding="utf-8")
        self.assertIn("except ModuleNotFoundError", source)


if __name__ == "__main__":
    unittest.main()
