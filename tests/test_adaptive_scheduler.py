import time
import unittest

from src.backend.adaptive_scheduler import AdaptiveProbeScheduler, ProbeTask


class TestAdaptiveScheduler(unittest.TestCase):
    def test_round_robin_prevents_subnet_starvation(self):
        tasks = [
            ProbeTask("icmp", "10.0.0.0/24", "a1", lambda: "a1"),
            ProbeTask("icmp", "10.0.1.0/24", "b1", lambda: "b1"),
            ProbeTask("icmp", "10.0.0.0/24", "a2", lambda: "a2"),
            ProbeTask("icmp", "10.0.1.0/24", "b2", lambda: "b2"),
        ]

        scheduler = AdaptiveProbeScheduler(hard_limits={"icmp": 1, "tcp": 1, "snmp": 1, "wmi": 1})
        result = scheduler.run(tasks)

        dispatch_subnets = [entry[1] for entry in result["dispatch_order"] if entry[0] == "icmp"]
        self.assertEqual(dispatch_subnets[:4], ["10.0.0.0/24", "10.0.1.0/24", "10.0.0.0/24", "10.0.1.0/24"])

    def test_backpressure_never_exceeds_hard_worker_limit(self):
        call_state = {"index": 0}

        def flaky_probe():
            call_state["index"] += 1
            time.sleep(0.005)
            if call_state["index"] % 2 == 0:
                raise TimeoutError("simulated timeout")
            return {"ok": True}

        tasks = [
            ProbeTask("wmi", "10.10.0.0/24", f"host-{i}", flaky_probe)
            for i in range(12)
        ]

        scheduler = AdaptiveProbeScheduler(hard_limits={"icmp": 1, "tcp": 1, "snmp": 1, "wmi": 3}, latency_spike_seconds=0.001)
        result = scheduler.run(tasks)
        metrics = result["metrics"]["wmi"]

        self.assertLessEqual(metrics["max_in_flight"], 3)
        self.assertGreater(metrics["backpressure_events"], 0)

    def test_throughput_metrics_emitted_per_probe_type(self):
        tasks = [
            ProbeTask("icmp", "10.0.0.0/24", "icmp-1", lambda: {"ip": "10.0.0.1"}),
            ProbeTask("snmp", "10.0.0.0/24", "snmp-1", lambda: {"sysName": "edge-1"}),
        ]

        scheduler = AdaptiveProbeScheduler(hard_limits={"icmp": 2, "tcp": 2, "snmp": 2, "wmi": 2})
        result = scheduler.run(tasks)

        for probe in ("icmp", "tcp", "snmp", "wmi"):
            self.assertIn(probe, result["metrics"])
            self.assertIn("throughput_per_second", result["metrics"][probe])
            self.assertIn("submitted", result["metrics"][probe])
            self.assertIn("completed", result["metrics"][probe])

    def test_timeout_model_uses_latency_percentile(self):
        latencies = [0.001, 0.002, 0.004, 0.030]

        def make_probe(delay):
            def run():
                time.sleep(delay)
                return {"ok": True}

            return run

        tasks = [
            ProbeTask("tcp", "10.0.2.0/24", f"tcp-{idx}", make_probe(delay))
            for idx, delay in enumerate(latencies)
        ]

        scheduler = AdaptiveProbeScheduler(hard_limits={"icmp": 1, "tcp": 1, "snmp": 1, "wmi": 1})
        result = scheduler.run(tasks)
        tcp_metrics = result["metrics"]["tcp"]

        self.assertGreater(tcp_metrics["latency_p95_seconds"], 0)
        self.assertGreater(tcp_metrics["recommended_timeout_seconds"], tcp_metrics["latency_p95_seconds"])

    def test_dynamic_scaling_reacts_to_high_latency_variance(self):
        delays = [0.001, 0.030, 0.001, 0.030, 0.001, 0.030]

        def make_probe(delay):
            def run():
                time.sleep(delay)
                return {"ok": True}

            return run

        tasks = [
            ProbeTask("tcp", "10.0.3.0/24", f"tcp-{idx}", make_probe(delay))
            for idx, delay in enumerate(delays)
        ]

        scheduler = AdaptiveProbeScheduler(
            hard_limits={"icmp": 1, "tcp": 4, "snmp": 1, "wmi": 1},
            latency_spike_seconds=10.0,
            timeout_ratio_threshold=1.0,
            latency_variance_threshold=0.0001,
        )
        result = scheduler.run(tasks)

        self.assertLess(result["soft_limits"]["tcp"], 4)
        self.assertGreater(result["metrics"]["tcp"]["backpressure_events"], 0)

    def test_retry_policy_by_probe_and_failure_class(self):
        state = {"icmp": 0, "wmi": 0}

        def icmp_flaky():
            state["icmp"] += 1
            if state["icmp"] < 2:
                raise TimeoutError("icmp timeout")
            return {"ok": True}

        def wmi_flaky():
            state["wmi"] += 1
            raise TimeoutError("wmi timeout")

        tasks = [
            ProbeTask("icmp", "10.0.4.0/24", "icmp-host", icmp_flaky),
            ProbeTask("wmi", "10.0.4.0/24", "wmi-host", wmi_flaky),
        ]

        scheduler = AdaptiveProbeScheduler(hard_limits={"icmp": 1, "tcp": 1, "snmp": 1, "wmi": 1})
        result = scheduler.run(tasks)

        self.assertEqual(result["metrics"]["icmp"]["retry_attempts"], 1)
        self.assertEqual(result["metrics"]["wmi"]["retry_attempts"], 0)

    def test_global_concurrency_ceiling_is_enforced(self):
        def slow_probe():
            time.sleep(0.02)
            return {"ok": True}

        tasks = [
            ProbeTask("icmp", "10.0.5.0/24", f"icmp-{i}", slow_probe)
            for i in range(4)
        ]
        tasks += [
            ProbeTask("tcp", "10.0.6.0/24", f"tcp-{i}", slow_probe)
            for i in range(4)
        ]

        scheduler = AdaptiveProbeScheduler(
            hard_limits={"icmp": 4, "tcp": 4, "snmp": 1, "wmi": 1},
            global_worker_ceiling=2,
        )
        result = scheduler.run(tasks)

        self.assertLessEqual(result["max_global_in_flight"], 2)
        self.assertGreaterEqual(result["cpu_backpressure_events"], 1)


if __name__ == "__main__":
    unittest.main()
