from datetime import datetime, timezone
import hashlib
import json
import copy

PROVENANCE_SCHEMA_VERSION = "5.1.0"


def _iso_utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sanitize_credential_audit(cred_audit: dict) -> dict:
    if not cred_audit:
        return {}
    c = copy.deepcopy(cred_audit)
    for k in list(c.keys()):
        if k.lower() in ("credentials", "communities", "secrets", "secret", "values", "raw"):
            c[k] = "[REDACTED]"
    return c


def _fingerprint_for_credential_audit(cred_audit: dict) -> str:
    safe = _sanitize_credential_audit(cred_audit)
    j = json.dumps(safe, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(j.encode("utf-8")).hexdigest()


def make_provenance(
    collector_name: str,
    collector_version: str,
    module: str,
    function_name: str,
    task_id: str | None = None,
    config_snapshot: dict | None = None,
    credential_audit: dict | None = None,
    evidence: list | None = None,
    explainability: dict | None = None,
    schema_version: str = PROVENANCE_SCHEMA_VERSION,
) -> dict:
    """Create a lightweight provenance dictionary suitable for attaching to discovery summaries.

    - Redacts raw secrets from `credential_audit` and includes a fingerprint instead.
    - Keeps fields intentionally small and linkable to higher-level metadata.
    """

    prov = {
        "provenance_schema_version": schema_version,
        "collected_at": _iso_utc_now(),
        "collector": {"name": collector_name, "version": collector_version},
        "source": {"module": module, "function": function_name},
        "config_snapshot": config_snapshot or {},
        "credential_audit_summary": None,
        "evidence": evidence or [],
        "explainability": explainability or {},
    }

    if task_id:
        prov["source"]["task_id"] = task_id

    if credential_audit:
        safe = _sanitize_credential_audit(credential_audit)
        prov["credential_audit_summary"] = {
            "source": safe.get("source"),
            "credential_count": len(credential_audit.get("credentials") or []),
            "load_error": safe.get("load_error"),
            "cred_fingerprint": _fingerprint_for_credential_audit(credential_audit),
        }

    return prov
