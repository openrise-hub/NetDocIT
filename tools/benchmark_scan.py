"""Benchmark: compare subprocess-based ping against raw-socket ICMP scanner.

Usage:
    python tools/benchmark_scan.py 192.168.0.0/24          # single subnet
    python tools/benchmark_scan.py 192.168.0.0/24 10.0.0.0/24   # multiple
"""

import sys
import time

# Ensure project root is on sys.path
sys.path.insert(0, ".")

from src.backend.transports.icmp import IcmpScanner, _raw_socket_available
from src.backend.scanner import _iter_ips_for_subnets, _python_ping_sweep


def banner(text: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print("=" * 60)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python tools/benchmark_scan.py <cidr> [<cidr>...]")
        sys.exit(1)

    subnets = sys.argv[1:]

    banner(f"Benchmark: {' '.join(subnets)}")

    # Expand subnets to IP lists
    all_ips = _iter_ips_for_subnets(subnets)
    print(f"Targets expanded: {len(all_ips)} IPs")

    # ---- Raw-socket scanner ----
    raw_available = _raw_socket_available()
    print(f"Raw sockets available: {raw_available}")

    banner("Phase 1: _python_ping_sweep (integrated pipeline)")
    t0 = time.monotonic()
    results_old = _python_ping_sweep(subnets, timeout_seconds=30, concurrency=128)
    t1 = time.monotonic()
    dt_old = t1 - t0
    print(f"  Duration : {dt_old:.2f}s")
    print(f"  Hosts    : {len(results_old)}")
    macs = sum(1 for r in results_old if r.get("mac"))
    print(f"  With MAC : {macs}")

    # ---- Standalone raw-socket scanner (bypasses ARP pre-seed) ----
    if raw_available:
        banner("Phase 2: IcmpScanner.batch_ping (raw socket)")
        scanner = IcmpScanner(timeout_ms=500)
        t0 = time.monotonic()
        ping_results = scanner.batch_ping(all_ips)
        t1 = time.monotonic()
        dt_new = t1 - t0
        alive = sum(1 for v in ping_results.values() if v is not None)
        print(f"  Duration : {dt_new:.2f}s")
        print(f"  Alive    : {alive}")
        if dt_old > 0:
            print(f"  Speedup  : {dt_old / dt_new:.1f}x faster than subprocess path")

    banner("Done")


if __name__ == "__main__":
    main()
