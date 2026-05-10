import io
import json
import unittest
from unittest.mock import patch, MagicMock

from src.presentation.web.server import _Handler, _scan_state, _scan_lock


def _make_handler(path: str = "/", method: str = "GET", body: bytes | None = None):
    """Construct a handler bypassing the real __init__/parse_request chain."""
    h = _Handler.__new__(_Handler)
    h.path = path
    h.command = method
    h.headers = MagicMock()
    h.headers.get.return_value = str(len(body or b""))
    h.rfile = io.BytesIO(body or b"")
    h.wfile = io.BytesIO()
    h.responses = []

    def _send_response(code, message=None):
        h.responses.append(code)

    def _send_header(k, v):
        pass

    def _end_headers():
        pass

    h.send_response = _send_response
    h.send_header = _send_header
    h.end_headers = _end_headers

    def _json_response(data, status=200):
        h.send_response(status)
        body_out = json.dumps(data, default=str).encode("utf-8")
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(body_out)))
        h.end_headers()
        h.wfile.write(body_out)

    def _static_response(ct, content):
        if isinstance(content, str):
            content = content.encode("utf-8")
        h.send_response(200)
        h.send_header("Content-Type", ct)
        h.send_header("Content-Length", str(len(content)))
        h.end_headers()
        h.wfile.write(content)

    def _read_body():
        return body or b""

    h._json_response = _json_response
    h._static_response = _static_response
    h._read_body = _read_body

    return h


class TestDashboardServing(unittest.TestCase):
    def test_root_serves_html_when_present(self):
        h = _make_handler("/")
        h._serve_dashboard()
        self.assertIn(200, h.responses)


class TestApiDevices(unittest.TestCase):
    @patch("src.presentation.web.server.get_devices_sorted_by_ip")
    def test_returns_200(self, mock_devices):
        mock_devices.return_value = [
            ("192.168.0.1", "AA:BB:CC:DD:EE:FF", "router", "Linux", "TP-Link"),
        ]
        h = _make_handler("/api/devices")
        h.do_GET()
        self.assertIn(200, h.responses)


class TestApiSummary(unittest.TestCase):
    @patch("src.presentation.web.server.get_device_counts_by_os")
    @patch("src.presentation.web.server.get_all_subnets")
    def test_returns_200(self, mock_subnets, mock_counts):
        mock_counts.return_value = {"windows": 3, "appliances": 2}
        mock_subnets.return_value = ["192.168.0.0/24"]
        h = _make_handler("/api/summary")
        h.do_GET()
        self.assertIn(200, h.responses)


class TestApiScanStatus(unittest.TestCase):
    def test_returns_200(self):
        h = _make_handler("/api/scan/status")
        h.do_GET()
        self.assertIn(200, h.responses)


class TestApiScanStart(unittest.TestCase):
    def test_refuses_when_already_running(self):
        with _scan_lock:
            _scan_state["running"] = True
        try:
            h = _make_handler("/api/scan/start", method="POST", body=b'{"profile":"safe"}')
            h.do_POST()
            self.assertIn(409, h.responses)
        finally:
            with _scan_lock:
                _scan_state["running"] = False

    @patch("src.presentation.web.server.threading.Thread")
    def test_accepts_when_idle(self, mock_thread):
        with _scan_lock:
            _scan_state["running"] = False
        h = _make_handler("/api/scan/start", method="POST", body=b'{"profile":"balanced"}')
        h.do_POST()
        self.assertIn(200, h.responses)
        with _scan_lock:
            _scan_state["running"] = False


class TestApiExportCsv(unittest.TestCase):
    @patch("src.presentation.web.server.get_devices_sorted_by_ip")
    def test_returns_200(self, mock_devices):
        mock_devices.return_value = [
            ("192.168.0.1", "AA:BB:CC:DD:EE:FF", "router", "Linux", "TP-Link"),
        ]
        h = _make_handler("/api/export/csv")
        h.do_GET()
        self.assertIn(200, h.responses)


class TestApiExportJson(unittest.TestCase):
    @patch("src.presentation.web.server.get_all_subnets")
    @patch("src.presentation.web.server.get_device_counts_by_os")
    @patch("src.presentation.web.server.get_devices_sorted_by_ip")
    def test_returns_200(self, mock_devices, mock_counts, mock_subnets):
        mock_devices.return_value = []
        mock_counts.return_value = {"windows": 0, "appliances": 0}
        mock_subnets.return_value = []
        h = _make_handler("/api/export/json")
        h.do_GET()
        self.assertIn(200, h.responses)


class TestCorsOptions(unittest.TestCase):
    def test_options_returns_204(self):
        h = _make_handler("/api/devices", method="OPTIONS")
        h.do_OPTIONS()
        self.assertIn(204, h.responses)


class TestNotFound(unittest.TestCase):
    def test_bad_path_returns_404(self):
        h = _make_handler("/api/nope")
        h.do_GET()
        self.assertIn(404, h.responses)


class TestScanStateFields(unittest.TestCase):
    def test_scan_state_has_required_fields(self):
        expected = {"running", "phase", "found", "enriched", "started_at",
                    "finished_at", "error", "devices", "summary"}
        with _scan_lock:
            keys = set(_scan_state.keys())
        self.assertTrue(expected.issubset(keys))


if __name__ == "__main__":
    unittest.main()
