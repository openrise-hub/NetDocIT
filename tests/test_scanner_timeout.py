import unittest
from unittest.mock import patch

from src.backend.scanner import run_ps_script


class TestScannerTimeout(unittest.TestCase):
    @patch("src.backend.scanner.json.loads", return_value=[])
    @patch("src.backend.scanner.subprocess.run")
    @patch("src.backend.scanner.os.path.exists", return_value=True)
    def test_run_ps_script_uses_custom_timeout(self, _exists, mock_run, _loads):
        mock_run.return_value.stdout = "[]"

        run_ps_script("ping_sweep.ps1", timeout_seconds=35)

        self.assertEqual(mock_run.call_args.kwargs["timeout"], 35)

    @patch("src.backend.scanner.json.loads", return_value=[])
    @patch("src.backend.scanner.subprocess.run")
    @patch("src.backend.scanner.os.path.exists", return_value=True)
    def test_run_ps_script_defaults_timeout_when_invalid(self, _exists, mock_run, _loads):
        mock_run.return_value.stdout = "[]"

        run_ps_script("ping_sweep.ps1", timeout_seconds=0)

        self.assertEqual(mock_run.call_args.kwargs["timeout"], 60)


if __name__ == "__main__":
    unittest.main()
