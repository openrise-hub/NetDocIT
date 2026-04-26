import importlib
import sys
import types
import unittest
from unittest.mock import patch


class TestDiscoveryTimeouts(unittest.TestCase):
    def test_get_active_interfaces_forwards_timeout(self):
        fake_pysnmp = types.ModuleType("pysnmp")
        fake_hlapi = types.ModuleType("pysnmp.hlapi")

        with patch.dict(sys.modules, {"pysnmp": fake_pysnmp, "pysnmp.hlapi": fake_hlapi}):
            discovery = importlib.import_module("src.backend.discovery")

            with patch.object(discovery, "run_ps_script", return_value={"interfaces": []}) as run_ps_script:
                discovery.get_active_interfaces(timeout_seconds=45)
                run_ps_script.assert_called_once_with("env_discovery.ps1", timeout_seconds=45)


if __name__ == "__main__":
    unittest.main()
