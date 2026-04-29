import unittest

from src.backend.asset_identity import resolve_canonical_asset


class TestAssetIdentityResolver(unittest.TestCase):
    def test_mac_churn_keeps_same_canonical_asset(self):
        existing_assets = [
            {
                "canonical_key": "aa:bb:cc:dd:ee:ff|contoso|srv-01",
                "primary_mac": "AA-BB-CC-DD-EE-FF",
                "primary_vendor": "Contoso",
                "primary_hostname": "srv-01",
                "confidence": 0.95,
            }
        ]
        sighting = {
            "ip": "10.0.0.21",
            "mac": "11-22-33-44-55-66",
            "hostname": "srv-01",
            "vendor": "Contoso",
            "source": "snmp",
        }

        result = resolve_canonical_asset(sighting, existing_assets)

        self.assertEqual(result["state"], "merged")
        self.assertEqual(result["canonical_key"], "aa:bb:cc:dd:ee:ff|contoso|srv-01")
        self.assertIn("AA-BB-CC-DD-EE-FF", result["aliases"])
        self.assertIn("11-22-33-44-55-66", result["aliases"])

    def test_ambiguous_match_creates_conflict(self):
        existing_assets = [
            {
                "canonical_key": "asset-a",
                "primary_mac": "AA-BB-CC-DD-EE-FF",
                "primary_vendor": "Contoso",
                "primary_hostname": "lab-01",
                "confidence": 0.9,
            },
            {
                "canonical_key": "asset-b",
                "primary_mac": "AA-BB-CC-DD-EE-11",
                "primary_vendor": "Contoso",
                "primary_hostname": "lab-01",
                "confidence": 0.9,
            },
        ]
        sighting = {
            "ip": "10.0.0.50",
            "mac": "AA-BB-CC-DD-EE-99",
            "hostname": "lab-01",
            "vendor": "Contoso",
            "source": "icmp",
        }

        result = resolve_canonical_asset(sighting, existing_assets)

        self.assertEqual(result["state"], "conflict")
        self.assertEqual(result["conflict_reason"], "ambiguous_match")


if __name__ == "__main__":
    unittest.main()
