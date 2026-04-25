import unittest

from src.presentation.tui import DashboardApp


class TestDashboardRenderContract(unittest.TestCase):
    def test_dashboard_exposes_render_method(self):
        app = DashboardApp()
        self.assertTrue(hasattr(app, "render"))
        renderable = app.render()
        self.assertIsNotNone(renderable)


if __name__ == "__main__":
    unittest.main()
