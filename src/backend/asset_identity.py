from __future__ import annotations

from typing import Any


def _normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def _identity_key(candidate: dict[str, Any]) -> str:
    mac = _normalize(candidate.get("primary_mac") or candidate.get("mac"))
    vendor = _normalize(candidate.get("primary_vendor") or candidate.get("vendor"))
    hostname = _normalize(candidate.get("primary_hostname") or candidate.get("hostname"))
    return f"{mac}|{vendor}|{hostname}"


def resolve_canonical_asset(sighting: dict[str, Any], existing_assets: list[dict[str, Any]]) -> dict[str, Any]:
    sighting_mac = _normalize(sighting.get("mac"))
    sighting_vendor = _normalize(sighting.get("vendor"))
    sighting_hostname = _normalize(sighting.get("hostname"))

    scored: list[tuple[float, dict[str, Any]]] = []
    for asset in existing_assets:
        score = 0.0
        if sighting_mac and sighting_mac == _normalize(asset.get("primary_mac")):
            score += 0.7
        if sighting_vendor and sighting_vendor == _normalize(asset.get("primary_vendor")):
            score += 0.2
        if sighting_hostname and sighting_hostname == _normalize(asset.get("primary_hostname")):
            score += 0.2
        scored.append((score, asset))

    scored.sort(key=lambda item: (-item[0], _normalize(item[1].get("canonical_key"))))

    if not scored or scored[0][0] <= 0.0:
        return {
            "state": "new",
            "canonical_key": _identity_key(sighting),
            "confidence": 0.0,
            "aliases": [],
            "conflict_reason": None,
        }

    best_score = scored[0][0]
    tied = [item for item in scored if item[0] == best_score and item[0] > 0.0]
    if len(tied) > 1:
        return {
            "state": "conflict",
            "canonical_key": None,
            "confidence": best_score,
            "aliases": [],
            "conflict_reason": "ambiguous_match",
        }

    best_asset = scored[0][1]
    aliases = []
    for value in (best_asset.get("primary_mac"), sighting.get("mac"), sighting.get("hostname"), sighting.get("vendor")):
        normalized = _normalize(value)
        if normalized:
            aliases.append(str(value))

    return {
        "state": "merged",
        "canonical_key": best_asset.get("canonical_key"),
        "confidence": best_score,
        "aliases": aliases,
        "conflict_reason": None,
    }
