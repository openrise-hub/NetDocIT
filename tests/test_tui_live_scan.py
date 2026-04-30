from src.presentation.tui import DashboardApp


def test_live_scan_sort_filter_and_selection_details():
    app = DashboardApp()
    app.last_discovery_summary = {
        "provenance": {
            "collector": {"name": "netdocit", "version": "1.0"},
            "source": {"module": "src.backend.discovery", "function": "discover_all"},
            "credential_audit_summary": {"cred_fingerprint": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
        }
    }

    app.apply_scan_event("scan_targets_found", {
        "targets": [
            {"ip": "192.0.2.20", "hostname": "beta", "vendor": "VendorB"},
            {"ip": "192.0.2.10", "hostname": "alpha", "vendor": "VendorA"},
        ],
        "count": 2,
    })
    app.apply_scan_event("host_details_ready", {
        "host_data": [{"ip": "192.0.2.10", "hostname": "alpha", "confidence": 0.88}],
        "snmp_data": [{"ip": "192.0.2.20", "hostname": "beta", "vendor": "VendorB", "explainability": {"why": "match", "how": "snmp", "confidence": 0.91}}],
    })

    visible = app._live_visible_devices()
    assert visible[0]["ip"] == "192.0.2.10"
    assert visible[0]["_live_update_count"] == 2

    app.cycle_live_sort_mode()
    visible = app._live_visible_devices()
    assert [device["ip"] for device in visible] == ["192.0.2.10", "192.0.2.20"]

    app.toggle_live_filter_mode()
    visible = app._live_visible_devices()
    assert [device["ip"] for device in visible] == []

    app.toggle_live_filter_mode()
    app.live_scan_selected_index = 0
    detail_text = app._selected_device_detail_text(app._selected_live_device()[0])
    assert "192.0.2.10" in detail_text
    assert "Run Provenance" in detail_text
