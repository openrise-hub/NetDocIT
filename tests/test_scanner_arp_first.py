import unittest
from unittest.mock import patch

from src.backend.scanner import _python_ping_sweep


class TestScannerArpFirst(unittest.TestCase):
    @patch("src.backend.scanner.subprocess.run")
    def test_arp_table_filters_broadcast_entries(self, mock_run):
        mock_run.return_value.stdout = """
Interface: 192.168.0.186 --- 0x12
  Internet Address      Physical Address      Type
  192.168.0.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.0.255         ff-ff-ff-ff-ff-ff     static
  192.168.0.186         38-6b-1c-02-93-f4     dynamic
"""
        results = _python_ping_sweep(["192.168.0.0/24"], timeout_seconds=1)

        ips = [item["ip"] for item in results]
        self.assertIn("192.168.0.1", ips)
        self.assertIn("192.168.0.186", ips)
        self.assertNotIn("192.168.0.255", ips)

    @patch("src.backend.scanner.IcmpScanner.batch_ping")
    @patch("src.backend.scanner._iter_ips_for_subnets")
    @patch("src.backend.scanner._parse_arp_table")
    def test_arp_seed_does_not_skip_active_probing(self, mock_arp, mock_iter, mock_ping):
        mock_arp.return_value = {"192.168.0.1": "AA:BB:CC:DD:EE:FF"}
        mock_iter.return_value = ["192.168.0.1", "192.168.0.10"]
        mock_ping.return_value = {"192.168.0.10": 0.05}

        results = _python_ping_sweep(["192.168.0.0/24"], timeout_seconds=2)

        ips = [item["ip"] for item in results]
        self.assertIn("192.168.0.1", ips)
        self.assertIn("192.168.0.10", ips)


if __name__ == "__main__":
    unittest.main()
