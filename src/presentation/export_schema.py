from datetime import datetime, timezone
from typing import Any

EXPORT_SCHEMA_VERSION = "5.4.0"


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_export_package(
    *,
    discovery: dict[str, Any],
    devices: list[Any],
    device_stats: dict[str, Any],
    topology: dict[str, Any] | None = None,
    report_name: str = "NetDocIT Inventory Export",
) -> dict[str, Any]:
    return {
        "export_schema_version": EXPORT_SCHEMA_VERSION,
        "generated_at": _iso_utc_now(),
        "report_name": report_name,
        "device_count": len(devices or []),
        "device_stats": device_stats,
        "subnet_count": len(discovery.get("subnets", []) or []),
        "discovery": discovery,
        "topology": topology or {},
    }