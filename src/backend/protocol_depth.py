from typing import Any

from .service_fingerprint import resolve_service_identity


def build_service_identity_summary(discovery_summary: dict[str, Any]) -> dict[str, Any]:
    evidence_items: list[dict[str, Any]] = []

    for item in discovery_summary.get("snmp_data", []):
        confidence = 0.9 if item.get("sysDescr") else 0.8
        evidence_items.append(
            {
                "service_hint": "snmp",
                "confidence": confidence,
                "transport": "udp",
            }
        )

    for item in discovery_summary.get("host_data", []):
        if item.get("hostname"):
            evidence_items.append(
                {
                    "service_hint": "wmi",
                    "confidence": 0.6,
                    "transport": "wmi",
                }
            )

    if not evidence_items:
        return {
            "display_name": "unknown",
            "state": "ambiguous",
            "confidence": 0.0,
            "candidates": [],
            "ranked_candidates": [],
        }

    return resolve_service_identity(evidence_items)
