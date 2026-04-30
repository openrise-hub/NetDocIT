import os
import json
from src.presentation.exporter import MarkdownGenerator


def test_export_includes_health(tmp_path):
    gen = MarkdownGenerator()
    subnet_count = 1
    dev_stats = {"windows": 0, "appliances": 0}
    devices = [("192.0.2.5", "aa:bb:cc:dd:ee:ff", "host1", "Cisco IOS", "Cisco")]
    health = {
        "health_schema_version": "5.2.0",
        "collected_at": "2026-04-30T12:00:00Z",
        "collector": {"name": "netdocit", "version": "0.1.0"},
    }

    out_file = tmp_path / "inventory_test_health.html"
    gen.save_html(subnet_count, dev_stats, devices, filename=str(out_file), health_report=health)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "5.2.0" in content
    start = content.find('<script id="health-data" type="application/json">')
    assert start != -1, "health JSON script tag missing"
    start2 = content.find('>', start) + 1
    end = content.find('</script>', start2)
    json_text = content[start2:end].strip()
    parsed = json.loads(json_text)
    assert parsed["health_schema_version"] == "5.2.0"
