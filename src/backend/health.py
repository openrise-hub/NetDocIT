from datetime import datetime, timezone
import hashlib
import json
import platform
import sys
import os
from typing import Optional, Dict, Any

HEALTH_SCHEMA_VERSION = "5.2.0"


def _iso_utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sanitize_config_snapshot(cfg: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not cfg:
        return {}
    # shallow copy and redact sensitive keys
    out = {}
    for k, v in cfg.items():
        kl = k.lower()
        if any(s in kl for s in ("secret", "credential", "credentials", "password", "token")):
            out[k] = "[REDACTED]"
        else:
            # keep primitive values only
            if isinstance(v, (str, int, float, bool, type(None))):
                out[k] = v
            else:
                out[k] = str(type(v))
    return out


def _fingerprint_from_credential_audit(cred_audit: Optional[Dict[str, Any]]) -> Optional[str]:
    if not cred_audit:
        return None
    try:
        j = json.dumps(cred_audit, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(j.encode("utf-8")).hexdigest()
    except Exception:
        return None


def make_health_report(
    collector_name: str,
    collector_version: str,
    config_snapshot: Optional[Dict[str, Any]] = None,
    credential_audit: Optional[Dict[str, Any]] = None,
    uptime_seconds: Optional[float] = None,
    dependencies: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Produce a compact health report describing runtime and dependency state.

    Keep the report small and privacy-safe; callers should not pass raw secrets here.
    """
    proc = {
        "pid": os.getpid(),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
    }

    report = {
        "health_schema_version": HEALTH_SCHEMA_VERSION,
        "collected_at": _iso_utc_now(),
        "collector": {"name": collector_name, "version": collector_version},
        "process": proc,
        "uptime_seconds": uptime_seconds,
        "metrics": {},
        "dependencies": dependencies or {},
        "config_snapshot": _sanitize_config_snapshot(config_snapshot),
        "credential_audit_fingerprint": _fingerprint_from_credential_audit(credential_audit),
    }

    return report
