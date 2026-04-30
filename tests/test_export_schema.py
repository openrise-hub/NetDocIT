import json
from src.presentation.export_schema import build_export_package


def test_build_export_package_schema():
    discovery = {"subnets": [{"cidr": "10.0.0.0/24", "tag": "Lab"}]}
    devices = [("192.0.2.5", "aa:bb:cc:dd:ee:ff", "host1", "Cisco IOS", "Cisco")]
    dev_stats = {"windows": 1, "appliances": 0}

    package = build_export_package(discovery=discovery, devices=devices, device_stats=dev_stats)
    assert package["export_schema_version"] == "5.4.0"
    assert package["report_name"] == "NetDocIT Inventory Export"
    assert package["subnet_count"] == 1
    assert package["device_count"] == 1
    assert package["discovery"]["subnets"][0]["cidr"] == "10.0.0.0/24"

    serialized = json.dumps(package)
    assert "5.4.0" in serialized
