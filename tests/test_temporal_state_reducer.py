import unittest

from src.backend.temporal_state import reduce_temporal_state


class TestTemporalStateReducer(unittest.TestCase):
    def test_first_sighting_initializes_new_state(self):
        previous_state = None
        current_scan = [
            {
                "canonical_asset_id": 1,
                "canonical_key": "asset-a",
                "sighting_key": "s1",
                "ip": "10.0.0.10",
            }
        ]

        result = reduce_temporal_state(previous_state, current_scan, scan_run_id="scan-1", absent_threshold=1)

        self.assertEqual(result["state_by_asset_id"][1]["lifecycle_state"], "new")
        self.assertEqual(result["state_by_asset_id"][1]["seen_count"], 1)
        self.assertEqual(result["state_by_asset_id"][1]["flap_count"], 0)

    def test_missing_and_returned_transitions_increment_flap_count(self):
        previous_state = {
            1: {
                "canonical_asset_id": 1,
                "first_seen": "2026-04-01 10:00:00",
                "last_seen": "2026-04-01 10:00:00",
                "seen_count": 1,
                "flap_count": 0,
                "lifecycle_state": "new",
                "last_transition_at": "2026-04-01 10:00:00",
            }
        }

        silent_result = reduce_temporal_state(previous_state, [], scan_run_id="scan-2", absent_threshold=1)
        returned_result = reduce_temporal_state(
            silent_result["state_by_asset_id"],
            [{"canonical_asset_id": 1, "canonical_key": "asset-a", "sighting_key": "s2", "ip": "10.0.0.10"}],
            scan_run_id="scan-3",
            absent_threshold=1,
        )

        self.assertEqual(silent_result["state_by_asset_id"][1]["lifecycle_state"], "silent")
        self.assertEqual(returned_result["state_by_asset_id"][1]["lifecycle_state"], "returned")
        self.assertGreaterEqual(returned_result["state_by_asset_id"][1]["flap_count"], 1)


if __name__ == "__main__":
    unittest.main()
