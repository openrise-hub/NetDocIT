import json
import pathlib
import subprocess
import unittest


class TestPingSweepScript(unittest.TestCase):
    def test_ping_sweep_runs_without_subnets(self):
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
