import unittest

from src.backend.scanner import get_scan_profile


class TestScanProfiles(unittest.TestCase):
    def test_known_scan_profiles(self):
        self.assertEqual(get_scan_profile("safe")["script_timeout"], 90)
        self.assertEqual(get_scan_profile("balanced")["script_timeout"], 60)
        self.assertEqual(get_scan_profile("aggressive")["script_timeout"], 35)

    def test_unknown_scan_profile_defaults_to_balanced(self):
        self.assertEqual(get_scan_profile("unknown")["script_timeout"], 60)


if __name__ == "__main__":
    unittest.main()
