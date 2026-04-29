import unittest

from src.backend.protocol_depth import build_service_identity_summary


class TestProtocolDepthSummary(unittest.TestCase):
    def test_snmp_data_produces_service_identity_summary(self):
        summary = build_service_identity_summary(
            {
                "snmp_data": [
                    {
                        "ip": "10.0.0.20",
                        "sysName": "core-switch-1",
                        "sysDescr": "Cisco IOS Software",
                    },
                    {
                        "ip": "10.0.0.21",
                        "sysName": "core-switch-2",
                        "sysDescr": "Cisco IOS Software",
                    }
                ],
                "host_data": [],
            }
        )

        self.assertEqual(summary["display_name"], "snmp")
        self.assertEqual(summary["state"], "known")
        self.assertGreaterEqual(summary["confidence"], 0.8)
        self.assertEqual(summary["ranked_candidates"][0]["service_name"], "snmp")


if __name__ == "__main__":
    unittest.main()
