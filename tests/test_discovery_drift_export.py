import json
from src.presentation.exporter import MarkdownGenerator


def test_export_includes_drift(tmp_path):
    gen = MarkdownGenerator()
    subnet_count = 1
    dev_stats = {"windows": 0, "appliances": 0}
    devices = [("192.0.2.5", "aa:bb:cc:dd:ee:ff", "host1", "Cisco IOS", "Cisco")]
    drift = {
        "drift_schema_version": "5.3.0",
        "collected_at": "2026-04-30T12:00:00Z",
        "summary": {"added": 1, "removed": 0, "modified": 0},
    }

    out_file = tmp_path / "inventory_test_drift.html"
    gen.save_html(subnet_count, dev_stats, devices, filename=str(out_file), drift_report=drift)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "5.3.0" in content
    start = content.find('<script id="drift-data" type="application/json">')
    assert start != -1
    start2 = content.find('>', start) + 1
    end = content.find('</script>', start2)
    parsed = json.loads(content[start2:end].strip())
    assert parsed["drift_schema_version"] == "5.3.0"
