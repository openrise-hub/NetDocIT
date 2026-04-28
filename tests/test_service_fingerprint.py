import unittest

from src.backend.service_fingerprint import resolve_service_identity


class TestServiceFingerprint(unittest.TestCase):
    def test_conflicting_evidence_stays_unknown(self):
        identity = resolve_service_identity([
            {"service_hint": "dns", "confidence": 0.91, "transport": "udp"},
            {"service_hint": "snmp", "confidence": 0.88, "transport": "udp"},
        ])
        self.assertEqual(identity["display_name"], "unknown")
        self.assertEqual(identity["state"], "ambiguous")

    def test_strong_single_service_promotes_identity(self):
        identity = resolve_service_identity([
            {"service_hint": "dns", "confidence": 0.95, "transport": "udp"},
            {"service_hint": "dns", "confidence": 0.90, "transport": "udp"},
        ])
        self.assertEqual(identity["display_name"], "dns")
        self.assertEqual(identity["state"], "known")


if __name__ == "__main__":
    unittest.main()
