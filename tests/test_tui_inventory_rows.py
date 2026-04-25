import unittest

from src.presentation.tui import DashboardApp


class TestTuiInventoryRows(unittest.TestCase):
    def test_inventory_accepts_tuple_rows(self):
        app = DashboardApp()
        app.state = "INVENTORY"
        app.devices = [("192.168.1.10", "AA-BB-CC-DD-EE-FF", "host-a", "Windows 11", "Contoso")]
        panel = app.make_main_view()
        self.assertIsNotNone(panel)


if __name__ == "__main__":
    unittest.main()
