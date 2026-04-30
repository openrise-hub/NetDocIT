import unittest

from src.backend.safety_profiles import (
    resolve_safety_profile,
    evaluate_safety_abort,
    SafetyProfile,
)


class TestSafetyProfiles(unittest.TestCase):
    def test_resolve_safety_profile_business_hours(self):
        prof = resolve_safety_profile("safe", current_hour=10)
        self.assertEqual(prof.name, "safe")
        self.assertEqual(prof.time_window, "business-hours")
        self.assertAlmostEqual(prof.max_timeout_ratio, 0.2)

    def test_resolve_safety_profile_off_hours_aggressive(self):
        prof = resolve_safety_profile("aggressive", current_hour=22)
        self.assertEqual(prof.name, "aggressive")
        self.assertEqual(prof.time_window, "off-hours")
        self.assertTrue(prof.max_timeout_ratio >= 0.4)

    def test_evaluate_safety_abort_on_timeout(self):
        prof = SafetyProfile("t", "safe", "business-hours", 1000, 0.1, 0, True)
        reason = evaluate_safety_abort(prof, run_duration_seconds=1.0, timeout_ratio=0.2, backpressure_events=0, scan_error=False)
        self.assertEqual(reason, "safety_profile_abort")

    def test_evaluate_safety_abort_on_backpressure(self):
        prof = SafetyProfile("t", "safe", "business-hours", 1000, 0.5, 0, True)
        reason = evaluate_safety_abort(prof, run_duration_seconds=1.0, timeout_ratio=0.0, backpressure_events=1, scan_error=False)
        self.assertEqual(reason, "safety_profile_abort")

    def test_evaluate_safety_abort_on_scan_error(self):
        prof = SafetyProfile("t", "safe", "business-hours", 1000, 0.5, 5, True)
        reason = evaluate_safety_abort(prof, run_duration_seconds=1.0, timeout_ratio=0.0, backpressure_events=0, scan_error=True)
        self.assertEqual(reason, "safety_scan_error")


if __name__ == "__main__":
    unittest.main()
import unittest

from src.backend.safety_profiles import resolve_safety_profile


class TestSafetyProfiles(unittest.TestCase):
    def test_safe_profile_is_conservative_during_business_hours(self):
        profile = resolve_safety_profile("safe", current_hour=10)

        self.assertEqual(profile.name, "safe")
        self.assertEqual(profile.default_scan_profile, "safe")
        self.assertEqual(profile.time_window, "business-hours")
        self.assertTrue(profile.abort_on_scan_error)
        self.assertLessEqual(profile.max_timeout_ratio, 0.2)

    def test_unknown_profile_falls_back_to_safe_defaults(self):
        profile = resolve_safety_profile("unknown", current_hour=23)

        self.assertEqual(profile.name, "safe")
        self.assertEqual(profile.default_scan_profile, "safe")
        self.assertEqual(profile.time_window, "off-hours")
        self.assertEqual(profile.max_runtime_seconds, 1800)


if __name__ == "__main__":
    unittest.main()