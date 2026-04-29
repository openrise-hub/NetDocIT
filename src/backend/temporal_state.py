from __future__ import annotations

from typing import Any


def reduce_temporal_state(
    previous_state: dict[int, dict[str, Any]] | None,
    current_scan: list[dict[str, Any]],
    scan_run_id: str,
    absent_threshold: int = 1,
) -> dict[str, Any]:
    previous_state = previous_state or {}
    current_by_asset_id = {
        int(item["canonical_asset_id"]): item for item in current_scan if item.get("canonical_asset_id") is not None
    }
    next_state: dict[int, dict[str, Any]] = {}
    events: list[dict[str, Any]] = []

    for asset_id, current in current_by_asset_id.items():
        prior = previous_state.get(asset_id)
        if prior is None:
            next_state[asset_id] = {
                "canonical_asset_id": asset_id,
                "first_seen": scan_run_id,
                "last_seen": scan_run_id,
                "seen_count": 1,
                "flap_count": 0,
                "lifecycle_state": "new",
                "last_transition_at": scan_run_id,
            }
            events.append(
                {
                    "canonical_asset_id": asset_id,
                    "event_type": "first_seen",
                    "previous_state": None,
                    "next_state": "new",
                    "event_reason": "initial_observation",
                    "event_payload": current,
                }
            )
            continue

        seen_count = int(prior.get("seen_count", 0)) + 1
        flap_count = int(prior.get("flap_count", 0))
        previous_lifecycle_state = str(prior.get("lifecycle_state", "new"))
        if previous_lifecycle_state == "silent":
            flap_count += 1
            lifecycle_state = "returned"
        elif previous_lifecycle_state == "missing":
            flap_count += 1
            lifecycle_state = "returned"
        else:
            lifecycle_state = previous_lifecycle_state if previous_lifecycle_state in {"new", "returned"} else "returned"

        next_state[asset_id] = {
            "canonical_asset_id": asset_id,
            "first_seen": prior.get("first_seen", scan_run_id),
            "last_seen": scan_run_id,
            "seen_count": seen_count,
            "flap_count": flap_count,
            "lifecycle_state": lifecycle_state,
            "last_transition_at": scan_run_id,
        }
        events.append(
            {
                "canonical_asset_id": asset_id,
                "event_type": "sighting",
                "previous_state": prior.get("lifecycle_state"),
                "next_state": lifecycle_state,
                "event_reason": "confirmed_sighting",
                "event_payload": current,
            }
        )

    absent_asset_ids = set(previous_state) - set(current_by_asset_id)
    for asset_id in absent_asset_ids:
        prior = previous_state[asset_id]
        previous_lifecycle_state = str(prior.get("lifecycle_state", "new"))
        if absent_threshold <= 0:
            next_state[asset_id] = dict(prior)
            continue

        next_flap_count = int(prior.get("flap_count", 0))
        if previous_lifecycle_state != "silent":
            next_flap_count += 1

        next_state[asset_id] = {
            "canonical_asset_id": asset_id,
            "first_seen": prior.get("first_seen", scan_run_id),
            "last_seen": prior.get("last_seen", scan_run_id),
            "seen_count": int(prior.get("seen_count", 0)),
            "flap_count": next_flap_count,
            "lifecycle_state": "silent",
            "last_transition_at": scan_run_id,
        }
        events.append(
            {
                "canonical_asset_id": asset_id,
                "event_type": "missing",
                "previous_state": prior.get("lifecycle_state"),
                "next_state": "silent",
                "event_reason": "asset_absent_in_current_scan",
                "event_payload": {"scan_run_id": scan_run_id, "absent_threshold": absent_threshold},
            }
        )

    return {"state_by_asset_id": next_state, "events": events}
