import json
import pathlib
import shutil
import subprocess
import unittest
from unittest.mock import patch


class TestPingSweepScript(unittest.TestCase):
    @patch("tests.test_ping_sweep_script.shutil.which", return_value=None)
    @patch("tests.test_ping_sweep_script.subprocess.run")
    def test_ping_sweep_skips_when_powershell_missing(self, mock_run, _mock_which):
        with self.assertRaises(unittest.SkipTest):
            self.test_ping_sweep_runs_without_subnets()

        mock_run.assert_not_called()

    def test_ping_sweep_runs_without_subnets(self):
        if shutil.which("powershell") is None:
            self.skipTest("powershell is not available on this runner")

        script = pathlib.Path(__file__).resolve().parent.parent / "src" / "backend" / "scripts" / "ping_sweep.ps1"
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        parsed = json.loads(result.stdout.strip() or "[]")
        self.assertIsInstance(parsed, list)


if __name__ == "__main__":
    unittest.main()
