import os
import json
from src.presentation.exporter import MarkdownGenerator


def test_export_includes_provenance(tmp_path):
    gen = MarkdownGenerator()
    subnet_count = 1
    dev_stats = {"windows": 0, "appliances": 0}
    devices = [("192.0.2.5", "aa:bb:cc:dd:ee:ff", "host1", "Cisco IOS", "Cisco")]
    provenance = {
        "provenance_schema_version": "5.1.0",
        "collected_at": "2026-04-30T12:00:00Z",
        "collector": {"name": "netdocit", "version": "0.1.0"},
    }

    out_file = tmp_path / "inventory_test.html"
    # call save_html with provenance kwarg (exporter will be updated to accept this)
    gen.save_html(subnet_count, dev_stats, devices, filename=str(out_file), provenance=provenance)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    # ensure provenance schema version appears in output
    assert "5.1.0" in content
    # ensure provenance block is valid JSON when extracted
    # find the script tag content if present
    start = content.find('<script id="provenance-data" type="application/json">')
    assert start != -1, "provenance JSON script tag missing"
    start2 = content.find('>', start) + 1
    end = content.find('</script>', start2)
    json_text = content[start2:end].strip()
    parsed = json.loads(json_text)
    assert parsed["provenance_schema_version"] == "5.1.0"
