"""Incremental scan support — skip expensive enrichment for stable hosts.

When a network has been scanned before, most hosts don't change between
runs.  This module queries the database for previously-observed IPs and
their temporal state, then splits the target list into:

* **cached** — IPs seen recently and marked stable; skip WMI/SNMP probes,
  reuse previously-collected host/SMNP data from the database.
* **fresh**  — everything else; enrich normally with the full pipeline.

A light ARP table pre-seed still runs for all targets (essentially free).
ICMP probing is not skipped — raw sockets make it fast regardless.
"""

from __future__ import annotations

from typing import Any

from .database import get_db_connection


def _get_known_ips() -> dict[str, dict[str, Any]]:
    """Query the database for all previously-sighted IPs with temporal state.

    Returns ``{ip: {lifecycle_state, seen_count, flap_count, canonical_asset_id}}``.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT s.ip, t.lifecycle_state, t.seen_count, t.flap_count,
                   s.canonical_asset_id
            FROM asset_sightings s
            JOIN asset_temporal_state t
              ON t.canonical_asset_id = s.canonical_asset_id
            WHERE s.ip IS NOT NULL
              AND s.canonical_asset_id IS NOT NULL
            ORDER BY s.id DESC
            """
        )
        result: dict[str, dict[str, Any]] = {}
        for ip, state, count, flaps, asset_id in cursor.fetchall():
            if ip and ip not in result:
                result[ip] = {
                    "lifecycle_state": state,
                    "seen_count": int(count or 0),
                    "flap_count": int(flaps or 0),
                    "canonical_asset_id": int(asset_id or 0),
                }
        return result


def is_stable(state: dict[str, Any]) -> bool:
    """Return True if a known host is stable enough to skip enrichment."""
    lifecycle = str(state.get("lifecycle_state", "")).lower()
    if lifecycle in {"silent", "missing"}:
        return False
    seen = int(state.get("seen_count", 0) or 0)
    flaps = int(state.get("flap_count", 0) or 0)
    return seen >= 2 and flaps == 0


def split_targets(found_ips: list[str]) -> tuple[list[str], list[str]]:
    """Split discovered IPs into *cached* (skip enrichment) and *fresh* (enrich).

    Returns ``(cached_ips, fresh_ips)``.
    """
    known = _get_known_ips()
    cached: list[str] = []
    fresh: list[str] = []
    for ip in found_ips:
        state = known.get(ip)
        if state and is_stable(state):
            cached.append(ip)
        else:
            fresh.append(ip)
    return cached, fresh


def get_cached_host_data(ips: list[str]) -> list[dict[str, Any]]:
    """Return host-enum-style data for previously-enriched IPs."""
    if not ips:
        return []
    placeholders = ",".join("?" for _ in ips)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f"""
            SELECT s.ip, s.mac, s.hostname, a.primary_vendor, s.vendor
            FROM asset_sightings s
            JOIN canonical_assets a ON a.id = s.canonical_asset_id
            WHERE s.ip IN ({placeholders})
              AND s.hostname IS NOT NULL
            ORDER BY s.id DESC
            """,
            ips,
        )
        seen: set[str] = set()
        results: list[dict[str, Any]] = []
        for ip, mac, hostname, primary_vendor, vendor in cursor.fetchall():
            if ip in seen:
                continue
            seen.add(ip)
            results.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "os": "Windows (cached)",
                "vendor": primary_vendor or vendor or "Unknown (cached)",
            })
        return results

