import unittest

from src.backend.evidence_model import EvidenceRecord, ServiceCandidate


class TestEvidenceModel(unittest.TestCase):
    def test_evidence_record_tracks_transport_and_confidence(self):
        record = EvidenceRecord(
            target="10.0.0.10",
            transport="udp",
            service_hint="dns",
            payload={"banner": "BIND 9.18"},
            confidence=0.82,
        )

        self.assertEqual(record.target, "10.0.0.10")
        self.assertEqual(record.transport, "udp")
        self.assertEqual(record.service_hint, "dns")
        self.assertEqual(record.confidence, 0.82)

    def test_service_candidate_stays_unknown_when_uncertain(self):
        candidate = ServiceCandidate(service_name="dns", confidence=0.42, evidence_count=2)

        self.assertFalse(candidate.is_promotable())
        self.assertEqual(candidate.display_name(), "unknown")


if __name__ == "__main__":
    unittest.main()
