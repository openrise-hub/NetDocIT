from src.backend.drift import make_drift_report


def test_make_drift_report_basic():
    baseline = ["10.0.0.0/24", "192.0.2.0/24"]
    current = ["10.0.0.0/24", "198.51.100.0/24"]

    report = make_drift_report(current, baseline)
    assert report["drift_schema_version"] == "5.3.0"
    assert report["summary"]["added"] == 1
    assert report["summary"]["removed"] == 1
    ids = [c["id"] for c in report["changes"]]
    assert "198.51.100.0/24" in ids
    assert "192.0.2.0/24" in ids
