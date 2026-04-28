from typing import Any


def _normalize_banner(value: str | None) -> str:
    return str(value or "").strip().lower()


def probe_dns(target: str, port: int, transport_response: dict[str, Any]) -> dict[str, Any]:
    banner = _normalize_banner(transport_response.get("banner"))
    return {
        "target": target,
        "port": port,
        "service_hint": "dns",
        "normalized_banner": banner,
        "service_state": "known" if banner else "unknown",
    }


def probe_snmp(target: str, port: int, transport_response: dict[str, Any]) -> dict[str, Any]:
    banner = _normalize_banner(transport_response.get("banner"))
    service_state = "known" if "snmp" in banner else "unknown"
    return {
        "target": target,
        "port": port,
        "service_hint": "snmp",
        "normalized_banner": banner,
        "service_state": service_state,
    }


def probe_ntp(target: str, port: int, transport_response: dict[str, Any]) -> dict[str, Any]:
    banner = _normalize_banner(transport_response.get("banner"))
    return {
        "target": target,
        "port": port,
        "service_hint": "ntp",
        "normalized_banner": banner,
        "service_state": "known" if banner else "unknown",
    }
