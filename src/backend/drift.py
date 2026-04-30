from datetime import datetime, timezone
from typing import List, Dict, Any

DRIFT_SCHEMA_VERSION = "5.3.0"


def _iso_utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def make_drift_report(current_subnets: List[str], baseline_subnets: List[str]) -> Dict[str, Any]:
    """Create a small drift report comparing current subnets (list of CIDR strings)
    against a baseline list. Returns added/removed and a summary.
    """
    cur_set = set(current_subnets or [])
    base_set = set(baseline_subnets or [])

    added = sorted(list(cur_set - base_set))
    removed = sorted(list(base_set - cur_set))

    changes = []
    for c in added:
        changes.append({"type": "subnet", "action": "added", "id": c, "details": {"before": None, "after": {"cidr": c}}, "significance": "medium"})
    for c in removed:
        changes.append({"type": "subnet", "action": "removed", "id": c, "details": {"before": {"cidr": c}, "after": None}, "significance": "high"})

    summary = {"added": len(added), "removed": len(removed), "modified": 0}

    report = {
        "drift_schema_version": DRIFT_SCHEMA_VERSION,
        "collected_at": _iso_utc_now(),
        "baseline_count": len(baseline_subnets or []),
        "current_count": len(current_subnets or []),
        "changes": changes,
        "summary": summary,
    }
    return report
