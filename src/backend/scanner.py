import subprocess
import json
import os
import re
import socket
import concurrent.futures
import ipaddress
from typing import Iterable

from .runtime_paths import resource_path
from .transports.icmp import IcmpScanner


SCAN_PROFILES = {
    "safe": {"script_timeout": 180},
    "balanced": {"script_timeout": 120},
    "aggressive": {"script_timeout": 35},
}


def get_scan_profile(name):
    if name is None:
        return dict(SCAN_PROFILES["safe"])
    profile_name = str(name).lower()
    return dict(SCAN_PROFILES.get(profile_name, SCAN_PROFILES["balanced"]))

def run_ps_script(script_name, args=None, timeout_seconds=60):
    # execute a script from the scripts folder and return json
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        timeout_seconds = 60
    # Special-case the ping sweep to provide a fast, portable ARP-first implementation
    if script_name == "ping_sweep.ps1":
        targets = args or []
        try:
            return _python_ping_sweep(targets, timeout_seconds)
        except Exception as e:
            return {"error": f"ping_sweep failure: {e}"}

    script_path = resource_path("src", "backend", "scripts", script_name)
    
    if not os.path.exists(script_path):
        return {"error": f"Script not found: {script_name}"}

    cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path]
    if args:
        cmd.extend(args)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=timeout_seconds)
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return [] # return empty on timeout
    except subprocess.CalledProcessError as e:
        return {"error": f"Script failed: {e.stderr}"}
    except json.JSONDecodeError:
        return {"error": "Script output was not valid JSON"}


_MAC_PATTERN = re.compile(r"[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}")


def _normalize_mac(raw: str) -> str | None:
    if not raw or not isinstance(raw, str):
        return None
    hex_only = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(hex_only) != 12:
        return None
    return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2)).upper()


def _build_subnet_networks(subnet_list):
    if not subnet_list:
        return []
    networks = []
    for subnet in subnet_list:
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
        except Exception:
            continue
        if network.prefixlen <= 0 or network.prefixlen >= 32:
            continue
        if network.is_loopback or network.is_multicast or network.is_unspecified or network.is_reserved or network.is_link_local:
            continue
        networks.append(network)
    return networks


def _parse_arp_table(subnet_list=None):
    """Parse the system ARP table (Windows `arp -a`).

    Returns a {ip: mac} mapping.  Normalises MAC addresses to colon-separated
    uppercase (``00:11:22:33:44:55``).  When ``subnet_list`` is provided only
    entries that fall within one of the supplied CIDRs are returned.
    """
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=True)
        lines = proc.stdout.splitlines()
    except Exception:
        return {}

    networks = _build_subnet_networks(subnet_list)

    result: dict[str, str] = {}
    for line in lines:
        match = _MAC_PATTERN.search(line)
        if not match:
            continue
        mac_raw = match.group(0)
        mac = _normalize_mac(mac_raw)
        if not mac:
            continue

        parts = line.strip().split()
        for p in parts:
            try:
                ip_addr = ipaddress.IPv4Address(p)
            except Exception:
                continue
            if ip_addr.is_multicast or ip_addr.is_loopback or ip_addr.is_unspecified or ip_addr.is_reserved or ip_addr.is_link_local:
                continue
            if networks:
                if not any(ip_addr in net and ip_addr not in (net.network_address, net.broadcast_address) for net in networks):
                    continue
            result[str(ip_addr)] = mac
            break

    return result


def _icmp_ping(ip: str, timeout_ms: int = 500) -> bool:
    """Perform a single ICMP ping using system `ping` command. Returns True if alive."""
    try:
        # Windows: -n 1 pings, -w timeout in ms
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip]
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode == 0
    except Exception:
        return False


def _tcp_connect(ip: str, port: int = 80, timeout_s: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except Exception:
        return False


def _iter_ips_for_subnets(subnets: Iterable[str]) -> list[str]:
    ips = []
    for s in subnets:
        try:
            net = ipaddress.IPv4Network(s, strict=False)
            # skip very large ranges; keep to /16 or smaller
            if net.num_addresses > 65536:
                continue
            for addr in net.hosts():
                ips.append(str(addr))
        except Exception:
            continue
    return ips


def _python_ping_sweep(subnets, timeout_seconds=60, concurrency=64):
    """ARP-first fast ping sweep for the provided subnet list.

    Returns a list of dicts similar to the PowerShell script output: [{"ip": "x.x.x.x", ...}, ...]
    """
    if subnets is None:
        subnets = []
    subnet_list = [s for s in (subnets or []) if isinstance(s, str) and s]

    arp_map = _parse_arp_table(subnet_list)

    seeded_ips = list(arp_map.keys())
    ips_to_scan = _iter_ips_for_subnets(subnet_list)
    if seeded_ips:
        seeded_set = set(seeded_ips)
        ips_to_scan = [ip for ip in ips_to_scan if ip not in seeded_set]
    if not ips_to_scan:
        unique_ips = sorted(set(seeded_ips))
        return [{"ip": ip, "mac": arp_map.get(ip), "hostname": ip} for ip in unique_ips]

    timeout_ms = min(1000, max(150, int((timeout_seconds / 10) * 1000)))
    responsive = list(seeded_ips)

    scanner = IcmpScanner(timeout_ms=timeout_ms)
    ping_results = scanner.batch_ping(ips_to_scan)
    for ip, rtt in ping_results.items():
        if rtt is not None:
            responsive.append(ip)

    if len(set(responsive)) <= len(set(seeded_ips)):
        ports = [22, 80, 443, 445, 3389, 135, 139, 8080, 8443]
        max_candidates = min(len(ips_to_scan), max(128, int(timeout_seconds * 32)))
        tcp_candidates = ips_to_scan[:max_candidates]
        tcp_timeout = max(0.2, min(0.5, timeout_seconds / 200))
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            tcp_futs = {}
            for ip in tcp_candidates:
                for p in ports:
                    tcp_futs[ex.submit(_tcp_connect, ip, p, tcp_timeout)] = (ip, p)
            try:
                for fut in concurrent.futures.as_completed(tcp_futs, timeout=max(1, timeout_seconds / 2)):
                    try:
                        ok = fut.result()
                    except Exception:
                        ok = False
                    if ok:
                        ip, p = tcp_futs[fut]
                        responsive.append(ip)
            except TimeoutError:
                pass

    unique_ips = sorted(set(responsive))
    refreshed_arp = _parse_arp_table(subnet_list)
    arp_map = {**arp_map, **refreshed_arp}
    return [{"ip": ip, "mac": arp_map.get(ip), "hostname": ip} for ip in unique_ips]

if __name__ == "__main__":
    print("Scanner module initialized.")
