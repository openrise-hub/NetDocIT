import unittest

from src.backend.service_fingerprint import resolve_service_identity


class TestProtocolDepthBenchmarks(unittest.TestCase):
    def test_identity_output_includes_confidence_and_ranked_candidates(self):
        identity = resolve_service_identity([
            {"service_hint": "dns", "confidence": 0.96, "transport": "udp"},
            {"service_hint": "dns", "confidence": 0.93, "transport": "udp"},
        ])

        self.assertEqual(identity["state"], "known")
        self.assertEqual(identity["display_name"], "dns")
        self.assertIn("confidence", identity)
        self.assertIn("ranked_candidates", identity)
        self.assertGreaterEqual(identity["confidence"], 0.9)
        self.assertEqual(identity["ranked_candidates"][0]["service_name"], "dns")


if __name__ == "__main__":
    unittest.main()
