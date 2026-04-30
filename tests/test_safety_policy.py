import unittest

from src.backend.safety_policy import ScopePolicy, evaluate_scope_policy


class TestSafetyPolicy(unittest.TestCase):
    def test_deny_list_blocks_a_subnet(self):
        policy = ScopePolicy(
            allow_subnets=frozenset({"10.0.0.0/24"}),
            deny_subnets=frozenset({"10.0.1.0/24"}),
            allow_hosts=frozenset(),
            deny_hosts=frozenset(),
            max_hosts=50,
            max_packets_per_second=200,
            max_concurrency=8,
        )

        decision = evaluate_scope_policy(
            candidate_subnets=["10.0.1.0/24"],
            candidate_hosts=[],
            policy=policy,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "policy_denied_scope")
        self.assertIn("deny-list", decision.violations[0])

    def test_host_cap_blocks_over_large_scope(self):
        policy = ScopePolicy(
            allow_subnets=frozenset(),
            deny_subnets=frozenset(),
            allow_hosts=frozenset(),
            deny_hosts=frozenset(),
            max_hosts=2,
            max_packets_per_second=200,
            max_concurrency=8,
        )

        decision = evaluate_scope_policy(
            candidate_subnets=["10.0.0.0/24"],
            candidate_hosts=["10.0.0.10", "10.0.0.11", "10.0.0.12"],
            policy=policy,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "policy_host_cap_exceeded")
        self.assertEqual(decision.effective_limits["max_hosts"], 2)

    def test_host_deny_list_blocks_a_host(self):
        policy = ScopePolicy(
            allow_subnets=frozenset(),
            deny_subnets=frozenset(),
            allow_hosts=frozenset(),
            deny_hosts=frozenset({"10.0.0.99"}),
            max_hosts=50,
            max_packets_per_second=200,
            max_concurrency=8,
        )

        decision = evaluate_scope_policy(
            candidate_subnets=["10.0.0.0/24"],
            candidate_hosts=["10.0.0.99"],
            policy=policy,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "policy_denied_scope")
        self.assertIn("deny-list", decision.violations[0])

    def test_policy_keeps_rate_and_concurrency_limits(self):
        policy = ScopePolicy(
            allow_subnets=frozenset(),
            deny_subnets=frozenset(),
            allow_hosts=frozenset(),
            deny_hosts=frozenset(),
            max_hosts=50,
            max_packets_per_second=120,
            max_concurrency=6,
        )

        decision = evaluate_scope_policy(
            candidate_subnets=["10.0.2.0/24"],
            candidate_hosts=[],
            policy=policy,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.effective_limits["max_packets_per_second"], 120)
        self.assertEqual(decision.effective_limits["max_concurrency"], 6)


if __name__ == "__main__":
    unittest.main()