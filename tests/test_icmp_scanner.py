import socket
import struct
import unittest
from unittest.mock import patch, MagicMock

from src.backend.transports.icmp import (
    ICMP_ECHO_REQUEST,
    ICMP_ECHO_REPLY,
    _checksum,
    _build_echo_request,
    _subprocess_ping,
    _raw_socket_available,
    IcmpScanner,
)


class TestChecksum(unittest.TestCase):
    def test_empty_payload(self):
        self.assertEqual(_checksum(b""), 0xFFFF)

    def test_known_vector(self):
        # Echo request with seq=0, id=0, zero checksum
        pkt = struct.pack("!BBHHH", 8, 0, 0, 0, 0) + struct.pack("!d", 0.0)
        csum = _checksum(pkt)
        self.assertIsInstance(csum, int)
        self.assertGreaterEqual(csum, 0)
        self.assertLessEqual(csum, 0xFFFF)

    def test_echo_request_has_valid_checksum(self):
        pkt = _build_echo_request(1, 0x1234)
        csum_calculated = _checksum(pkt)
        self.assertEqual(csum_calculated, 0)


class TestBuildEchoRequest(unittest.TestCase):
    def test_correct_type_and_code(self):
        pkt = _build_echo_request(42, 0xABCD)
        self.assertEqual(pkt[0], ICMP_ECHO_REQUEST)  # type
        self.assertEqual(pkt[1], 0)                   # code

    def test_identifier_and_sequence(self):
        pkt = _build_echo_request(42, 0xABCD)
        recv_id = (pkt[4] << 8) + pkt[5]
        recv_seq = (pkt[6] << 8) + pkt[7]
        self.assertEqual(recv_id, 0xABCD)
        self.assertEqual(recv_seq, 42)

    def test_checksum_is_network_order(self):
        pkt = _build_echo_request(1, 1)
        stored_checksum = (pkt[2] << 8) + pkt[3]
        self.assertNotEqual(stored_checksum, 0)


class TestRawSocketAvailable(unittest.TestCase):
    @patch("src.backend.transports.icmp.socket.socket")
    def test_returns_true_when_socket_opens(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        self.assertTrue(_raw_socket_available())

    @patch("src.backend.transports.icmp.socket.socket")
    def test_returns_false_on_permission_error(self, mock_sock_cls):
        mock_sock_cls.side_effect = PermissionError("access denied")
        self.assertFalse(_raw_socket_available())

    @patch("src.backend.transports.icmp.socket.socket")
    def test_returns_false_on_os_error(self, mock_sock_cls):
        mock_sock_cls.side_effect = OSError("no raw support")
        self.assertFalse(_raw_socket_available())


class TestSubprocessPing(unittest.TestCase):
    @patch("src.backend.transports.icmp.subprocess.run")
    def test_returns_true_when_ping_succeeds(self, mock_run):
        mock_run.return_value.returncode = 0
        self.assertTrue(_subprocess_ping("8.8.8.8", 500))

    @patch("src.backend.transports.icmp.subprocess.run")
    def test_returns_false_when_ping_fails(self, mock_run):
        mock_run.return_value.returncode = 1
        self.assertFalse(_subprocess_ping("192.168.0.99", 500))

    @patch("src.backend.transports.icmp.subprocess.run")
    def test_returns_false_on_exception(self, mock_run):
        mock_run.side_effect = OSError("no ping")
        self.assertFalse(_subprocess_ping("10.0.0.1", 500))


def _build_mock_echo_reply(identifier: int, seq: int, send_time: float) -> bytes:
    """Build a minimal ICMP echo reply byte string as received on a raw socket."""
    # Real reply: 20-byte IP header + 8-byte ICMP header + payload
    ip_header = b"\x45\x00\x00\x1c" + b"\x00" * 8 + b"\x00" * 8
    icmp_header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, 0, identifier, seq)
    # recompute checksum
    payload = struct.pack("!d", send_time)
    tmp = icmp_header[:2] + b"\x00\x00" + icmp_header[4:] + payload
    csum = _checksum(tmp)
    icmp_header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, csum, identifier, seq)
    return ip_header + icmp_header + payload


class TestIcmpScannerBatchRaw(unittest.TestCase):
    def setUp(self):
        self.scanner = IcmpScanner(timeout_ms=200)

    @patch("src.backend.transports.icmp.socket.socket")
    @patch("src.backend.transports.icmp.select.select")
    def test_alive_host_returns_rtt(self, mock_select, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        reply_bytes = _build_mock_echo_reply(self.scanner._identifier, 1, 100.0)
        mock_sock.recvfrom.return_value = (reply_bytes, ("192.168.0.1", 0))
        mock_select.side_effect = [([mock_sock], [], []), ([], [], [])]

        with patch.object(self.scanner, "_raw_ok", True):
            results = self.scanner.batch_ping(["192.168.0.1"])

        self.assertIn("192.168.0.1", results)
        self.assertIsNotNone(results["192.168.0.1"])


class TestIcmpScannerBatchSubprocess(unittest.TestCase):
    @patch("src.backend.transports.icmp._subprocess_ping")
    def test_returns_alive_for_responding_host(self, mock_ping):
        mock_ping.return_value = True
        scanner = IcmpScanner(timeout_ms=200)
        with patch.object(scanner, "_raw_ok", False):
            results = scanner.batch_ping(["192.168.0.1", "192.168.0.2"])
        self.assertIsNotNone(results["192.168.0.1"])
        self.assertIsNotNone(results["192.168.0.2"])

    @patch("src.backend.transports.icmp._subprocess_ping")
    def test_returns_none_for_dead_host(self, mock_ping):
        mock_ping.return_value = False
        scanner = IcmpScanner(timeout_ms=200)
        with patch.object(scanner, "_raw_ok", False):
            results = scanner.batch_ping(["10.0.0.99"])
        self.assertIsNone(results["10.0.0.99"])


class TestIcmpScannerEmptyInput(unittest.TestCase):
    def test_empty_list_returns_empty_dict(self):
        scanner = IcmpScanner()
        self.assertEqual(scanner.batch_ping([]), {})


class TestIcmpScannerUsesRawSockets(unittest.TestCase):
    @patch("src.backend.transports.icmp._raw_socket_available")
    def test_exposes_raw_socket_flag(self, mock_avail):
        mock_avail.return_value = True
        scanner = IcmpScanner()
        self.assertTrue(scanner.uses_raw_sockets)


class TestIcmpScannerFallbackBehaviour(unittest.TestCase):
    @patch("src.backend.transports.icmp._raw_socket_available")
    def test_raw_failure_falls_back_to_subprocess(self, mock_avail):
        mock_avail.return_value = False
        scanner = IcmpScanner(timeout_ms=100)
        self.assertFalse(scanner.uses_raw_sockets)
        with patch.object(scanner, "_batch_subprocess") as mock_sub:
            mock_sub.return_value = {"10.0.0.1": None}
            result = scanner.batch_ping(["10.0.0.1"])
            mock_sub.assert_called_once()
            self.assertEqual(result, {"10.0.0.1": None})


if __name__ == "__main__":
    unittest.main()
