from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SafetyProfile:
    name: str
    default_scan_profile: str
    time_window: str
    max_runtime_seconds: int
    max_timeout_ratio: float
    max_backpressure_events: int
    abort_on_scan_error: bool


def resolve_safety_profile(scan_profile: str, current_hour: int | None = None) -> SafetyProfile:
    normalized = str(scan_profile or "safe").lower()
    if normalized not in {"safe", "balanced", "aggressive"}:
        normalized = "safe"

    hour = current_hour
    if hour is None:
        import time

        hour = time.localtime().tm_hour

    is_business_hours = 8 <= int(hour) < 18
    time_window = "business-hours" if is_business_hours else "off-hours"

    if normalized == "aggressive":
        return SafetyProfile(
            name="aggressive",
            default_scan_profile="aggressive",
            time_window=time_window,
            max_runtime_seconds=900 if is_business_hours else 1200,
            max_timeout_ratio=0.4 if is_business_hours else 0.5,
            max_backpressure_events=2 if is_business_hours else 3,
            abort_on_scan_error=True,
        )

    if normalized == "balanced":
        return SafetyProfile(
            name="balanced",
            default_scan_profile="balanced",
            time_window=time_window,
            max_runtime_seconds=1200 if is_business_hours else 1500,
            max_timeout_ratio=0.25 if is_business_hours else 0.35,
            max_backpressure_events=1 if is_business_hours else 2,
            abort_on_scan_error=True,
        )

    return SafetyProfile(
        name="safe",
        default_scan_profile="safe",
        time_window=time_window,
        max_runtime_seconds=1800,
        max_timeout_ratio=0.2,
        max_backpressure_events=0,
        abort_on_scan_error=True,
    )


def safety_profile_to_summary(profile: SafetyProfile) -> dict[str, object]:
    return {
        "name": profile.name,
        "default_scan_profile": profile.default_scan_profile,
        "time_window": profile.time_window,
        "max_runtime_seconds": profile.max_runtime_seconds,
        "max_timeout_ratio": profile.max_timeout_ratio,
        "max_backpressure_events": profile.max_backpressure_events,
        "abort_on_scan_error": profile.abort_on_scan_error,
    }


def evaluate_safety_abort(
    profile: SafetyProfile,
    *,
    run_duration_seconds: float,
    timeout_ratio: float,
    backpressure_events: int,
    scan_error: bool,
) -> str | None:
    if scan_error and profile.abort_on_scan_error:
        return "safety_scan_error"
    if run_duration_seconds > profile.max_runtime_seconds:
        return "safety_runtime_budget_exceeded"
    if timeout_ratio >= profile.max_timeout_ratio:
        return "safety_profile_abort"
    if backpressure_events > profile.max_backpressure_events:
        return "safety_profile_abort"
    return None