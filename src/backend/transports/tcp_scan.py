"""TCP port scanner using connect() with per-port timeouts.

Scans a configurable port list across live hosts using ThreadPoolExecutor
for concurrency.  Fast enough for discovery use-cases (top ~13 ports on a
/24 subnet in under 30 seconds).
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443]
DEFAULT_TIMEOUT_S = 0.2
DEFAULT_CONCURRENCY = 128
RECV_BYTES = 256


def _connect_port(ip: str, port: int, timeout_s: float) -> dict:
    """Probe a single TCP port.  Grabs an initial banner after connect."""
    result: dict = {"ip": ip, "port": port, "open": False, "banner": None, "rtt_ms": None}
    try:
        t0 = time.monotonic()
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            result["open"] = True
            result["rtt_ms"] = round((time.monotonic() - t0) * 1000, 1)
            sock.settimeout(0.3)
            try:
                data = sock.recv(RECV_BYTES)
                try:
                    result["banner"] = data.decode("utf-8", errors="replace")
                except Exception:
                    result["banner"] = data.hex()
            except socket.timeout:
                pass
            except OSError:
                pass
    except (TimeoutError, socket.timeout, OSError):
        pass
    except Exception:
        pass
    return result


class TcpPortScanner:
    """Configurable TCP port scanner."""

    def __init__(
        self,
        ports: list[int] | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_workers: int = DEFAULT_CONCURRENCY,
    ):
        self.ports = list(ports or DEFAULT_PORTS)
        self.timeout_s = max(0.05, float(timeout_s))
        self.max_workers = min(512, max(1, int(max_workers)))

    def scan_hosts(self, ips: list[str]) -> dict[str, list[dict]]:
        """Scan all configured ports on every IP.

        Returns ``{ip: [{"port": 80, "open": True, "banner": ..., "rtt_ms": 2.3}, ...]}``
        """
        if not ips:
            return {}

        results: dict[str, list[dict]] = {ip: [] for ip in ips}
        tasks: list[tuple[str, int]] = []
        for ip in ips:
            for port in self.ports:
                tasks.append((ip, port))

        if not tasks:
            return results

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {
                ex.submit(_connect_port, ip, port, self.timeout_s): (ip, port)
                for ip, port in tasks
            }
            for fut in as_completed(futures):
                try:
                    entry = fut.result()
                    results[entry["ip"]].append(entry)
                except Exception:
                    pass

        return results

    def open_ports(self, ips: list[str]) -> dict[str, list[int]]:
        """Shorthand: returns only open port numbers per IP."""
        host_results = self.scan_hosts(ips)
        return {
            ip: sorted(r["port"] for r in entries if r["open"])
            for ip, entries in host_results.items()
        }
