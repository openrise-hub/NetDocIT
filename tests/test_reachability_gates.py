import unittest

from src.backend.reachability import choose_reachability_path


class TestReachabilityGates(unittest.TestCase):
    def test_local_targets_use_arp_before_icmp(self):
        decision = choose_reachability_path("192.168.1.42", is_local_target=True)
        self.assertEqual(decision.primary_transport, "arp")
        self.assertEqual(decision.fallback_transport, "icmp")

    def test_remote_targets_use_icmp_only(self):
        decision = choose_reachability_path("10.10.10.10", is_local_target=False)
        self.assertEqual(decision.primary_transport, "icmp")
        self.assertIsNone(decision.fallback_transport)


if __name__ == "__main__":
    unittest.main()
