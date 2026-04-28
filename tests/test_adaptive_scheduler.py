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


if __name__ == "__main__":
    unittest.main()
