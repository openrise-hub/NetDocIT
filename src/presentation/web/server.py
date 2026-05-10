"""Lightweight HTTP server and REST API for the NetDocIT web dashboard.

Powered by stdlib ``http.server`` — zero extra dependencies.
"""

from __future__ import annotations

import csv
import io
import json
import os
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from ...backend.database import (
    get_devices_sorted_by_ip,
    get_device_counts_by_os,
    get_all_subnets,
    get_all_interfaces,
    get_all_routes,
    get_logs,
    init_db,
)
from ...backend.runtime_paths import runtime_path

_script_dir = Path(__file__).resolve().parent
_DASHBOARD_HTML = _script_dir / "dashboard.html"

# ---- scan state (shared across threads) ----------------------------------

_scan_lock = threading.Lock()
_scan_state: dict[str, Any] = {
    "running": False,
    "phase": "idle",
    "found": 0,
    "enriched": 0,
    "started_at": None,
    "finished_at": None,
    "error": None,
    "devices": [],
    "summary": {},
}

_scan_thread: threading.Thread | None = None


def _run_scan_in_background(profile: str = "balanced", timeout: float | None = None):
    """Called in a daemon thread; updates _scan_state as discovery progresses."""
    from ...backend.discovery import discover_all
    from ...backend.database import ingest_live_data, add_log_entry

    global _scan_state
    with _scan_lock:
        _scan_state["running"] = True
        _scan_state["phase"] = "starting"
        _scan_state["found"] = 0
        _scan_state["enriched"] = 0
        _scan_state["started_at"] = time.time()
        _scan_state["finished_at"] = None
        _scan_state["error"] = None
        _scan_state["devices"] = []
        _scan_state["summary"] = {}

    def progress_callback(event: str, payload: dict | None = None):
        payload = payload or {}
        with _scan_lock:
            _scan_state["phase"] = event
            if event == "scan_targets_found":
                _scan_state["found"] = int(payload.get("count", 0))
                _scan_state["devices"] = payload.get("targets", [])
            elif event == "host_details_ready":
                _scan_state["enriched"] = len(payload.get("host_data", [])) + len(
                    payload.get("snmp_data", [])
                )

    try:
        discovery = discover_all(
            log_fn=None,
            progress_fn=progress_callback,
            scan_profile=profile,
            script_timeout_seconds=timeout,
        )
        ingest_live_data(discovery)
        devices = get_devices_sorted_by_ip()
        with _scan_lock:
            _scan_state["phase"] = "completed"
            _scan_state["finished_at"] = time.time()
            _scan_state["summary"] = discovery
            _scan_state["devices"] = [
                {
                    "ip": d[0],
                    "mac": d[1],
                    "hostname": d[2],
                    "os": d[3],
                    "vendor": d[4],
                }
                for d in devices
            ]
    except Exception as exc:
        with _scan_lock:
            _scan_state["phase"] = "error"
            _scan_state["error"] = str(exc)
            _scan_state["finished_at"] = time.time()
    finally:
        with _scan_lock:
            _scan_state["running"] = False


# ---- HTTP handler ---------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silence access logs

    def _json_response(self, data, status=200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _static_response(self, content_type, content):
        if isinstance(content, str):
            content = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            return self._serve_dashboard()
        if path == "/api/devices":
            return self._api_devices()
        if path == "/api/summary":
            return self._api_summary()
        if path == "/api/scan/status":
            return self._api_scan_status()
        if path == "/api/export/csv":
            return self._api_export_csv()
        if path == "/api/export/json":
            return self._api_export_json()

        self._json_response({"error": "not found"}, 404)

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/api/scan/start":
            body = self._read_body()
            try:
                params = json.loads(body) if body else {}
            except json.JSONDecodeError:
                params = {}
            profile = str(params.get("profile", "balanced"))
            timeout = params.get("timeout")
            if timeout is not None:
                timeout = float(timeout)
            return self._api_scan_start(profile, timeout)

        self._json_response({"error": "not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # -- endpoints ----------------------------------------------------------

    def _serve_dashboard(self):
        if _DASHBOARD_HTML.is_file():
            html = _DASHBOARD_HTML.read_text(encoding="utf-8")
            self._static_response("text/html; charset=utf-8", html)
        else:
            self._json_response({"error": "dashboard.html not found"}, 500)

    def _api_devices(self):
        devices = get_devices_sorted_by_ip()
        data = [
            {
                "ip": d[0],
                "mac": d[1],
                "hostname": d[2],
                "os": d[3],
                "vendor": d[4],
            }
            for d in devices
        ]
        with _scan_lock:
            live = _scan_state
        self._json_response({"devices": data, "live": live.get("devices", [])})

    def _api_summary(self):
        stats = get_device_counts_by_os()
        subnets = get_all_subnets()
        self._json_response({
            "windows_count": stats.get("windows", 0),
            "appliance_count": stats.get("appliances", 0),
            "subnet_count": len(subnets),
            "total_devices": stats.get("windows", 0) + stats.get("appliances", 0),
        })

    def _api_scan_status(self):
        with _scan_lock:
            state = dict(_scan_state)
        self._json_response(state)

    def _api_scan_start(self, profile: str, timeout: float | None):
        global _scan_thread

        with _scan_lock:
            if _scan_state["running"]:
                self._json_response({"error": "scan already running"}, 409)
                return

        _scan_thread = threading.Thread(
            target=_run_scan_in_background,
            args=(profile, timeout),
            daemon=True,
        )
        _scan_thread.start()
        self._json_response({"status": "started", "profile": profile})

    def _api_export_csv(self):
        devices = get_devices_sorted_by_ip()
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["IP", "MAC", "Hostname", "OS", "Vendor"])
        for d in devices:
            writer.writerow(d)
        self._static_response("text/csv; charset=utf-8", buf.getvalue())

    def _api_export_json(self):
        devices = get_devices_sorted_by_ip()
        data = {
            "devices": [
                {"ip": d[0], "mac": d[1], "hostname": d[2], "os": d[3], "vendor": d[4]}
                for d in devices
            ],
            "subnets": get_all_subnets(),
            "stats": get_device_counts_by_os(),
        }
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self._static_response("application/json; charset=utf-8", body)


# ---- public API -----------------------------------------------------------


def start_server(host: str = "127.0.0.1", port: int = 8080, open_browser: bool = True):
    """Launch the web dashboard server.  Blocks until Ctrl+C."""
    init_db()

    server = HTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}"

    print(f"NetDocIT web dashboard: {url}")
    print("Press Ctrl+C to stop.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()
