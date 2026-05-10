import socket
import unittest
from unittest.mock import patch, MagicMock

from src.backend.transports.tcp_scan import (
    _connect_port,
    TcpPortScanner,
    DEFAULT_PORTS,
    DEFAULT_TIMEOUT_S,
)
from src.backend.transports.fingerprint import (
    PORT_SERVICE_MAP,
    identify_service,
    classify_host_services,
    build_service_summary,
    _match_from_banner,
)


class TestPortServiceMap(unittest.TestCase):
    def test_known_ports_mapped(self):
        self.assertEqual(PORT_SERVICE_MAP[22], "ssh")
        self.assertEqual(PORT_SERVICE_MAP[80], "http")
        self.assertEqual(PORT_SERVICE_MAP[443], "https")
        self.assertEqual(PORT_SERVICE_MAP[3389], "rdp")
        self.assertEqual(PORT_SERVICE_MAP[445], "smb")


class TestConnectPort(unittest.TestCase):
    @patch("src.backend.transports.tcp_scan.socket.create_connection")
    def test_open_port_returns_correct_structure(self, mock_connect):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_connect.return_value.__enter__.return_value = mock_sock
        result = _connect_port("192.168.0.1", 22, 0.2)
        self.assertTrue(result["open"])
        self.assertEqual(result["port"], 22)
        self.assertIn("SSH", result["banner"])
        self.assertIsNotNone(result["rtt_ms"])

    @patch("src.backend.transports.tcp_scan.socket.create_connection")
    def test_closed_port_returns_open_false(self, mock_connect):
        mock_connect.side_effect = OSError("connection refused")
        result = _connect_port("192.168.0.1", 99, 0.1)
        self.assertFalse(result["open"])
        self.assertIsNone(result["banner"])

    @patch("src.backend.transports.tcp_scan.socket.create_connection")
    def test_timeout_returns_open_false(self, mock_connect):
        mock_connect.side_effect = socket.timeout("timed out")
        result = _connect_port("10.0.0.1", 80, 0.05)
        self.assertFalse(result["open"])

    @patch("src.backend.transports.tcp_scan.socket.create_connection")
    def test_empty_banner_when_nothing_received(self, mock_connect):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("no data")
        mock_connect.return_value.__enter__.return_value = mock_sock
        result = _connect_port("192.168.0.1", 3389, 0.2)
        self.assertTrue(result["open"])
        self.assertIsNone(result["banner"])


class TestTcpPortScanner(unittest.TestCase):
    @patch("src.backend.transports.tcp_scan._connect_port")
    def test_scan_hosts_returns_per_ip_entries(self, mock_connect):
        mock_connect.side_effect = lambda ip, port, timeout_s: {
            "ip": ip,
            "port": port,
            "open": port in {22, 80},
            "banner": "SSH-2.0" if port == 22 else None,
            "rtt_ms": 2.0,
        }
        scanner = TcpPortScanner(ports=[22, 80], timeout_s=0.1, max_workers=4)
        results = scanner.scan_hosts(["192.168.0.1", "192.168.0.2"])
        self.assertIn("192.168.0.1", results)
        self.assertIn("192.168.0.2", results)
        for entries in results.values():
            self.assertEqual(len(entries), 2)

    @patch("src.backend.transports.tcp_scan._connect_port")
    def test_open_ports_returns_only_open_port_numbers(self, mock_connect):
        mock_connect.side_effect = lambda ip, port, timeout_s: {
            "ip": ip,
            "port": port,
            "open": port == 80,
            "banner": None,
            "rtt_ms": 1.0,
        }
        scanner = TcpPortScanner(ports=[22, 80, 443])
        result = scanner.open_ports(["192.168.0.1"])
        self.assertEqual(result, {"192.168.0.1": [80]})

    def test_empty_hosts_returns_empty_dict(self):
        scanner = TcpPortScanner()
        self.assertEqual(scanner.scan_hosts([]), {})

    def test_default_ports_configured(self):
        scanner = TcpPortScanner()
        self.assertGreater(len(scanner.ports), 10)


class TestIdentifyService(unittest.TestCase):
    def test_port_80_produces_http_hint(self):
        result = identify_service(80, None)
        self.assertEqual(result["service_hint"], "http")
        self.assertEqual(result["transport"], "tcp")

    def test_ssh_banner_overrides_port_unknown(self):
        result = identify_service(9999, "SSH-2.0-OpenSSH")
        self.assertEqual(result["service_hint"], "ssh")
        self.assertGreater(result["confidence"], 0.6)

    def test_html_banner_overrides_http(self):
        result = identify_service(8080, "<html><body>")
        self.assertEqual(result["service_hint"], "http")

    def test_unknown_port_defaults(self):
        result = identify_service(12345, None)
        self.assertEqual(result["service_hint"], "unknown")
        self.assertLess(result["confidence"], 0.5)


class TestClassifyHostServices(unittest.TestCase):
    def test_filters_closed_ports(self):
        host_results = [
            {"port": 22, "open": True, "banner": "SSH-2.0"},
            {"port": 80, "open": False, "banner": None},
            {"port": 443, "open": True, "banner": None},
        ]
        evidence = classify_host_services(host_results)
        self.assertEqual(len(evidence), 2)
        hints = [e["service_hint"] for e in evidence]
        self.assertIn("ssh", hints)
        self.assertIn("https", hints)
        self.assertNotIn("http", hints)


class TestBuildServiceSummary(unittest.TestCase):
    def test_groups_services_per_ip(self):
        host_results = {
            "192.168.0.1": [
                {"port": 22, "open": True, "banner": "SSH-2.0"},
                {"port": 80, "open": True, "banner": "HTTP/1.0"},
                {"port": 443, "open": False, "banner": None},
            ],
            "192.168.0.2": [
                {"port": 3389, "open": True, "banner": None},
            ],
        }
        summary = build_service_summary(host_results)
        self.assertIn("192.168.0.1", summary)
        self.assertIn("192.168.0.2", summary)
        self.assertIn("ssh", summary["192.168.0.1"])
        self.assertIn("http", summary["192.168.0.1"])
        self.assertIn("rdp", summary["192.168.0.2"])


class TestMatchFromBanner(unittest.TestCase):
    def test_ssh_banner_detected(self):
        self.assertEqual(_match_from_banner("SSH-2.0-OpenSSH_8.9"), "ssh")

    def test_smtp_banner_detected(self):
        self.assertEqual(_match_from_banner("220 mail.example.com ESMTP"), "smtp")

    def test_ftp_banner_detected(self):
        self.assertEqual(_match_from_banner("220 FTP server ready"), "ftp")

    def test_html_detected(self):
        self.assertEqual(_match_from_banner("HTTP/1.0 200 OK"), "http")

    def test_empty_banner_returns_none(self):
        self.assertIsNone(_match_from_banner(""))

    def test_none_returns_none(self):
        self.assertIsNone(_match_from_banner(None))


class TestFingerprintModuleImports(unittest.TestCase):
    def test_port_service_map_completeness(self):
        for port in DEFAULT_PORTS:
            self.assertIn(port, PORT_SERVICE_MAP,
                          f"port {port} has no service mapping")

    def test_identify_service_returns_all_required_keys(self):
        result = identify_service(80, "HTTP/1.0 200 OK", rtt_ms=2.5)
        for key in ("service_hint", "confidence", "transport", "port", "banner", "rtt_ms"):
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
