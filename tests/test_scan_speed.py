import time
import unittest
from unittest.mock import patch

from src.backend.scanner import _python_ping_sweep


class TestScanSpeed(unittest.TestCase):
    @patch("src.backend.scanner._tcp_connect", return_value=False)
    @patch("src.backend.scanner._icmp_ping", return_value=False)
    @patch("src.backend.scanner._parse_arp_table", return_value=[])
    @patch("src.backend.scanner._iter_ips_for_subnets")
    def test_local_24_completes_under_10s(self, mock_iter, _arp, _icmp, _tcp):
        mock_iter.return_value = [f"192.168.0.{i}" for i in range(1, 255)]
        start = time.monotonic()
        _python_ping_sweep(["192.168.0.0/24"], timeout_seconds=10, concurrency=64)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 10.0)


if __name__ == "__main__":
    unittest.main()
