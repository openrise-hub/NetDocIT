from src.backend.telemetry import make_provenance


def test_make_provenance_basic_schema():
    cred_audit = {"source": "secrets-file", "credentials": ["public", "monitor"], "load_error": None}
    evidence = [
        {"type": "snmp_sysdescr", "id": "192.0.2.5", "confidence": 0.87, "why": "match", "how": "snmp_engine.poll(v2c)"}
    ]

    prov = make_provenance(
        collector_name="netdocit-collector",
        collector_version="0.0.0-test",
        module="src.backend.discovery",
        function_name="run_discovery",
        task_id="test-1",
        config_snapshot={"profile": "balanced", "timeout": 60, "secrets_file": "env:NETDOCIT_SECRETS_FILE (present)"},
        credential_audit=cred_audit,
        evidence=evidence,
        explainability={"summary": "test"},
    )

    assert prov["provenance_schema_version"] == "5.1.0"
    assert "collected_at" in prov and prov["collected_at"].endswith("Z")
    assert prov["collector"]["name"] == "netdocit-collector"
    assert prov["source"]["module"] == "src.backend.discovery"
    assert prov["source"]["task_id"] == "test-1"

    cas = prov["credential_audit_summary"]
    assert cas is not None
    assert "cred_fingerprint" in cas and len(cas["cred_fingerprint"]) == 64
    s = str(prov)
    assert "public" not in s and "monitor" not in s

    assert isinstance(prov["evidence"], list) and prov["evidence"][0]["why"] == "match"
