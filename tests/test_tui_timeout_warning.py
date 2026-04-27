import unittest

from src.presentation.tui import DashboardApp


class TestTuiTimeoutWarning(unittest.TestCase):
    def test_menu_shows_timeout_budget_warning(self):
        app = DashboardApp()
        app.state = "MENU"
        app.last_discovery_summary = {
            "scan_completion_state": "budget_exceeded",
            "run_duration_seconds": 5.0,
            "script_timeout_seconds": 3,
        }

        panel = app.make_main_view()

        self.assertIn("timeout budget", str(panel.renderable).lower())
        self.assertIn("5.0s", str(panel.renderable))
        self.assertIn("3s", str(panel.renderable))


if __name__ == "__main__":
    unittest.main()
