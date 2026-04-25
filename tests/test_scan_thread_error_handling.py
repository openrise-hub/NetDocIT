import pathlib
import unittest


class TestScanThreadErrorHandling(unittest.TestCase):
    def test_scan_thread_does_not_swallow_exceptions_silently(self):
        source = (pathlib.Path(__file__).resolve().parent.parent / "src" / "main.py").read_text(encoding="utf-8")
        self.assertNotIn("except Exception:\n                                    pass", source)


if __name__ == "__main__":
    unittest.main()
