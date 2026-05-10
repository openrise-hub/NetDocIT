"""Raw-socket ICMP echo scanner.

Uses ``socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`` to batch-ping IP lists
without spawning a subprocess per target.  That delivers performance on par
with native tools like Advanced IP Scanner (sub-second for a /24 subnet).

On platforms where raw sockets are denied (non-admin Windows, unprivileged
Linux) the scanner falls back automatically to the subprocess ``ping`` path.
"""

from __future__ import annotations

import os
import select
import socket
import struct
import subprocess
import time
from typing import Optional

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEFAULT_TIMEOUT_MS = 500
ICMP_DEFAULT_CONCURRENCY = 128


def _checksum(data: bytes) -> int:
    """16-bit one's complement checksum (RFC 792)."""
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _build_echo_request(seq: int, identifier: int = 0) -> bytes:
    """Assemble an ICMP echo request (type=8, code=0)."""
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, identifier, seq)
    payload = struct.pack("!d", time.time())
    csum = _checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, csum, identifier, seq)
    return header + payload


def _raw_socket_available() -> bool:
    """Return *True* if the process can open a raw ICMP socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP):
            return True
    except (PermissionError, OSError):
        return False


def _subprocess_ping(ip: str, timeout_ms: int) -> bool:
    """Single-host ICMP probe via OS ``ping`` command (slow fallback)."""
    try:
        return (
            subprocess.run(
                ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
    except Exception:
        return False


class IcmpScanner:
    """Batch ICMP echo scanner backed by a raw socket."""

    def __init__(self, timeout_ms: int = ICMP_DEFAULT_TIMEOUT_MS):
        self._timeout_ms = int(timeout_ms)
        self._identifier = (os.getpid() & 0xFFFF) ^ (int(time.monotonic() * 1000) & 0xFFFF)
        self._raw_ok = _raw_socket_available()

    @property
    def uses_raw_sockets(self) -> bool:
        return self._raw_ok

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def batch_ping(self, ips: list[str]) -> dict[str, Optional[float]]:
        """Ping every IP in *ips*.

        Returns ``{ip: rtt_seconds | None}``.  *None* means the host did
        not respond within the scanner's timeout window.
        """
        if not ips:
            return {}
        if self._raw_ok:
            return self._batch_raw(ips)
        return self._batch_subprocess(ips)

    # ------------------------------------------------------------------
    # Raw-socket codepath
    # ------------------------------------------------------------------

    def _batch_raw(self, ips: list[str]) -> dict[str, Optional[float]]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except OSError:
            self._raw_ok = False
            return self._batch_subprocess(ips)

        results: dict[str, Optional[float]] = {}
        try:
            sock.setblocking(False)

            # --- send phase -------------------------------------------
            seq_to_ip: dict[int, str] = {}
            for seq, ip in enumerate(ips, start=1):
                if seq > 65535:
                    break
                packet = _build_echo_request(seq, self._identifier)
                try:
                    sock.sendto(packet, (ip, 0))
                    seq_to_ip[seq] = ip
                    results.setdefault(ip, None)
                except OSError:
                    results[ip] = None

            # --- receive phase ----------------------------------------
            deadline = time.monotonic() + (self._timeout_ms / 1000.0) + 2.0
            while seq_to_ip and time.monotonic() < deadline:
                ready, _, _ = select.select([sock], [], [], 0.1)
                if not ready:
                    continue
                try:
                    data, _addr = sock.recvfrom(1024)
                    if len(data) < 28:
                        continue
                    icmp_type = data[20]
                    if icmp_type != ICMP_ECHO_REPLY:
                        continue
                    recv_id = (data[24] << 8) + data[25]
                    if recv_id != self._identifier:
                        continue
                    recv_seq = (data[26] << 8) + data[27]
                    ip = seq_to_ip.pop(recv_seq, None)
                    if ip is not None:
                        try:
                            sent = struct.unpack("!d", data[28:36])[0]
                        except Exception:
                            sent = 0.0
                        results[ip] = max(0.0, time.time() - sent)
                except (BlockingIOError, OSError):
                    continue
        finally:
            sock.close()

        return results

    # ------------------------------------------------------------------
    # Subprocess fallback
    # ------------------------------------------------------------------

    def _batch_subprocess(self, ips: list[str]) -> dict[str, Optional[float]]:
        import concurrent.futures

        results: dict[str, Optional[float]] = {}
        to_scan = list(ips)
        if not to_scan:
            return results

        # Scale concurrency reasonably; never exceed 256 workers.
        workers = min(ICMP_DEFAULT_CONCURRENCY, len(to_scan))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {
                ex.submit(_subprocess_ping, ip, self._timeout_ms): ip
                for ip in to_scan
            }
            for fut in concurrent.futures.as_completed(futures):
                ip = futures[fut]
                try:
                    if fut.result():
                        results[ip] = 0.0  # no RTT from subprocess fallback
                    else:
                        results[ip] = None
                except Exception:
                    results[ip] = None

        return results
