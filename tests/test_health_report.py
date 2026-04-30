from src.backend.health import make_health_report


def test_health_report_redacts_secrets():
    cfg = {"profile": "balanced", "snmp_secret": "public", "nested": {"a": 1}}
    cred_audit = {"source": "secrets-file", "credentials": ["public"]}

    report = make_health_report("netdocit", "0.1.0", config_snapshot=cfg, credential_audit=cred_audit, uptime_seconds=12.3)
    assert report["health_schema_version"] == "5.2.0"
    assert "collected_at" in report
    assert report["collector"]["name"] == "netdocit"
    # config snapshot should redact snmp_secret and not include nested dicts fully
    cs = report["config_snapshot"]
    assert cs.get("snmp_secret") == "[REDACTED]"
    assert isinstance(cs.get("nested"), str)
    # credential fingerprint present and is a 64-char hex
    assert isinstance(report.get("credential_audit_fingerprint"), str) and len(report.get("credential_audit_fingerprint")) == 64
