"""Service identification from TCP port scan results.

Feeds into the existing ``service_fingerprint.resolve_service_identity``
pipeline via ``evidence_model.EvidenceRecord``-compatible dicts.
"""

from __future__ import annotations

from typing import Any

PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    135: "msrpc",
    139: "netbios",
    443: "https",
    445: "smb",
    3389: "rdp",
    8080: "http-proxy",
    8443: "https-alt",
}

HTTP_PORTS = {80, 8080}
HTTPS_PORTS = {443, 8443}
MAIL_PORTS = {25}


def _normalize_banner(raw: str | None) -> str:
    return str(raw or "").strip().lower()


def _match_from_banner(banner: str) -> str | None:
    b = _normalize_banner(banner)
    if not b:
        return None
    if b.startswith("ssh-"):
        return "ssh"
    if "ftp" in b:
        return "ftp"
    if "smtp" in b or "mail" in b:
        return "smtp"
    if b.startswith("220"):
        return "smtp"
    if "http" in b or b.startswith("http/") or "<html" in b:
        return "http"
    return None


def identify_service(
    port: int, banner: str | None, rtt_ms: float | None = None
) -> dict[str, Any]:
    """Produce a single evidence item from a single port probe.

    Returns a dict with ``service_hint``, ``confidence``, ``transport`` and
    supporting metadata that the ``service_fingerprint`` pipeline can group
    and rank.
    """
    base_confidence = 0.3
    service_hint = PORT_SERVICE_MAP.get(port, "unknown")

    banner_match = _match_from_banner(banner) if banner else None
    if banner_match:
        service_hint = banner_match
        base_confidence = 0.7

    if service_hint in {"ssh", "rdp", "smb"}:
        base_confidence += 0.1

    confidence = min(0.95, base_confidence)

    return {
        "service_hint": service_hint,
        "confidence": confidence,
        "transport": "tcp",
        "port": port,
        "banner": _normalize_banner(banner),
        "rtt_ms": rtt_ms,
    }


def classify_host_services(
    host_results: list[dict],
) -> list[dict[str, Any]]:
    """Turn a TCP scan result list for one host into evidence items.

    Expected input is the output of ``TcpPortScanner.scan_hosts()[ip]``.
    """
    evidence: list[dict[str, Any]] = []
    for entry in host_results:
        if not entry.get("open"):
            continue
        item = identify_service(
            port=entry["port"],
            banner=entry.get("banner"),
            rtt_ms=entry.get("rtt_ms"),
        )
        evidence.append(item)
    return evidence


def build_service_summary(host_results_by_ip: dict[str, list[dict]]) -> dict[str, list[str]]:
    """Quick per-host summary: ``{ip: ["http", "ssh", ...]}``."""
    summary: dict[str, list[str]] = {}
    for ip, entries in host_results_by_ip.items():
        open_ports = [e["port"] for e in entries if e.get("open")]
        services = []
        for port in sorted(set(open_ports)):
            service = PORT_SERVICE_MAP.get(port, f"port-{port}")
            services.append(service)
        summary[ip] = sorted(set(services))
    return summary
