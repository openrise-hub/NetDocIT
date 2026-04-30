import json
import os


def _normalize_credentials(value):
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if not isinstance(value, list):
        return []

    normalized = []
    seen = set()
    for item in value:
        if not isinstance(item, str):
            continue
        candidate = item.strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def _base_audit(source):
    return {
        "source": source,
        "loaded": False,
        "credential_count": 0,
        "load_error": None,
        "rotation_due": None,
        "expires_at": None,
    }


def resolve_snmp_credentials(override=None, config=None):
    if config is None:
        config = {}

    override_credentials = _normalize_credentials(override)
    if override_credentials:
        audit = _base_audit("cli_override")
        audit["loaded"] = True
        audit["credential_count"] = len(override_credentials)
        return override_credentials, audit

    secrets_path = os.environ.get("NETDOCIT_SECRETS_FILE")
    if secrets_path:
        audit = _base_audit("external_file")
        try:
            with open(secrets_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError:
            audit["load_error"] = "secrets_file_not_found"
            return [], audit
        except json.JSONDecodeError:
            audit["load_error"] = "secrets_file_invalid_json"
            return [], audit
        except OSError:
            audit["load_error"] = "secrets_file_unreadable"
            return [], audit

        metadata = payload.get("metadata", {}) if isinstance(payload, dict) else {}
        credentials = _normalize_credentials(
            payload.get("credentials", {}).get("snmp", []) if isinstance(payload, dict) else []
        )
        audit["rotation_due"] = metadata.get("rotation_due")
        audit["expires_at"] = metadata.get("expires_at")

        if not credentials:
            audit["load_error"] = "secrets_snmp_credentials_missing"
            return [], audit

        audit["loaded"] = True
        audit["credential_count"] = len(credentials)
        return credentials, audit

    if str(os.environ.get("NETDOCIT_ENV", "")).lower() == "production":
        audit = _base_audit("external_file")
        audit["load_error"] = "secrets_file_required_in_production"
        return [], audit

    legacy_credentials = _normalize_credentials(
        config.get("credentials", {}).get("snmp", []) if isinstance(config, dict) else []
    )
    audit = _base_audit("legacy_config")
    audit["loaded"] = bool(legacy_credentials)
    audit["credential_count"] = len(legacy_credentials)
    return legacy_credentials, audit