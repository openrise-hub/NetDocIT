from collections import defaultdict
from typing import Any


def resolve_service_identity(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in evidence_items:
        grouped[str(item.get("service_hint", "unknown"))].append(item)

    ranked_candidates: list[dict[str, Any]] = []
    for service_name, items in grouped.items():
        evidence_count = len(items)
        average_confidence = sum(float(item.get("confidence", 0.0)) for item in items) / evidence_count
        ranked_candidates.append(
            {
                "service_name": service_name,
                "confidence": average_confidence,
                "evidence_count": evidence_count,
            }
        )

    ranked_candidates.sort(key=lambda item: (-float(item["confidence"]), -int(item["evidence_count"]), str(item["service_name"])))

    if len(ranked_candidates) != 1:
        best_candidate = ranked_candidates[0] if ranked_candidates else {"service_name": "unknown", "confidence": 0.0, "evidence_count": 0}
        return {
            "display_name": "unknown",
            "state": "ambiguous",
            "confidence": float(best_candidate["confidence"]),
            "candidates": [candidate["service_name"] for candidate in ranked_candidates],
            "ranked_candidates": ranked_candidates,
        }

    best_candidate = ranked_candidates[0]
    service_name = str(best_candidate["service_name"])
    confidence = float(best_candidate["confidence"])
    evidence_count = int(best_candidate["evidence_count"])

    if confidence >= 0.8 and evidence_count >= 2:
        return {
            "display_name": service_name,
            "state": "known",
            "confidence": confidence,
            "candidates": [service_name],
            "ranked_candidates": ranked_candidates,
        }

    return {
        "display_name": "unknown",
        "state": "ambiguous",
        "confidence": confidence,
        "candidates": [service_name],
        "ranked_candidates": ranked_candidates,
    }
