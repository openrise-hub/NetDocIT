import unittest
from unittest.mock import patch

from src.backend.scanner import _normalize_mac, _parse_arp_table


class TestNormalizeMac(unittest.TestCase):
    def test_dash_separated(self):
        self.assertEqual(_normalize_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")

    def test_colon_separated(self):
        self.assertEqual(_normalize_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")

    def test_no_separators(self):
        self.assertEqual(_normalize_mac("aabbccddeeff"), "AA:BB:CC:DD:EE:FF")

    def test_mixed_case(self):
        self.assertEqual(_normalize_mac("Aa-Bb-Cc-Dd-Ee-Ff"), "AA:BB:CC:DD:EE:FF")

    def test_invalid_length_returns_none(self):
        self.assertIsNone(_normalize_mac("aa-bb-cc-dd"))

    def test_empty_returns_none(self):
        self.assertIsNone(_normalize_mac(""))

    def test_none_returns_none(self):
        self.assertIsNone(_normalize_mac(None))

    def test_non_string_returns_none(self):
        self.assertIsNone(_normalize_mac(12345))


class TestParseArpTable(unittest.TestCase):
    WIN_OUTPUT = """
Interface: 192.168.0.186 --- 0x12
  Internet Address      Physical Address      Type
  192.168.0.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.0.42          11-22-33-44-55-66     dynamic
  10.0.0.1              77-88-99-aa-bb-cc     dynamic
"""

    @patch("src.backend.scanner.subprocess.run")
    def test_returns_ip_to_mac_mapping(self, mock_run):
        mock_run.return_value.stdout = self.WIN_OUTPUT
        result = _parse_arp_table()
        self.assertEqual(
            result,
            {
                "192.168.0.1": "AA:BB:CC:DD:EE:FF",
                "192.168.0.42": "11:22:33:44:55:66",
                "10.0.0.1": "77:88:99:AA:BB:CC",
            },
        )

    @patch("src.backend.scanner.subprocess.run")
    def test_filters_by_subnet(self, mock_run):
        mock_run.return_value.stdout = self.WIN_OUTPUT
        result = _parse_arp_table(["192.168.0.0/24"])
        self.assertEqual(
            result,
            {
                "192.168.0.1": "AA:BB:CC:DD:EE:FF",
                "192.168.0.42": "11:22:33:44:55:66",
            },
        )

    @patch("src.backend.scanner.subprocess.run")
    def test_excludes_broadcast_address(self, mock_run):
        mock_run.return_value.stdout = """
Interface: 192.168.0.186 --- 0x12
  Internet Address      Physical Address      Type
  192.168.0.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.0.255         ff-ff-ff-ff-ff-ff     static
"""
        result = _parse_arp_table(["192.168.0.0/24"])
        self.assertIn("192.168.0.1", result)
        self.assertNotIn("192.168.0.255", result)

    @patch("src.backend.scanner.subprocess.run")
    def test_excludes_loopback_and_multicast(self, mock_run):
        mock_run.return_value.stdout = """
Interface: 192.168.0.186 --- 0x12
  127.0.0.1             00-00-00-00-00-00     static
  224.0.0.1             01-00-5e-00-00-01     static
  192.168.0.1           aa-bb-cc-dd-ee-ff     dynamic
"""
        result = _parse_arp_table()
        self.assertIn("192.168.0.1", result)
        self.assertNotIn("127.0.0.1", result)
        self.assertNotIn("224.0.0.1", result)

    @patch("src.backend.scanner.subprocess.run")
    def test_subprocess_error_returns_empty(self, mock_run):
        mock_run.side_effect = OSError("arp not found")
        result = _parse_arp_table()
        self.assertEqual(result, {})

    @patch("src.backend.scanner.subprocess.run")
    def test_garbled_output_returns_empty(self, mock_run):
        mock_run.return_value.stdout = "not a real arp table output"
        result = _parse_arp_table()
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
