import unittest

from src.backend.probes.udp import probe_dns, probe_ntp, probe_snmp


class TestUdpServiceProbes(unittest.TestCase):
    def test_dns_probe_normalizes_banner_and_service_hint(self):
        result = probe_dns("10.0.0.53", port=53, transport_response={"banner": "BIND 9.18"})
        self.assertEqual(result["service_hint"], "dns")
        self.assertEqual(result["normalized_banner"], "bind 9.18")

    def test_snmp_probe_marks_unknown_on_generic_response(self):
        result = probe_snmp("10.0.0.20", port=161, transport_response={"banner": "response"})
        self.assertEqual(result["service_state"], "unknown")

    def test_ntp_probe_preserves_service_identity(self):
        result = probe_ntp("10.0.0.123", port=123, transport_response={"banner": "ntpd 4.2.8"})
        self.assertEqual(result["service_hint"], "ntp")


if __name__ == "__main__":
    unittest.main()
