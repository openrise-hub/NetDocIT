from __future__ import annotations

from collections import defaultdict, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
import time
from typing import Any, Callable


PROBE_TYPES = ("icmp", "tcp", "snmp", "wmi")


@dataclass(frozen=True)
class ProbeTask:
    probe_type: str
    subnet: str
    target: str
    run: Callable[[], Any]


class AdaptiveProbeScheduler:
    def __init__(
        self,
        hard_limits: dict[str, int] | None = None,
        timeout_ratio_threshold: float = 0.3,
        latency_spike_seconds: float = 0.8,
    ) -> None:
        base_limits = {"icmp": 32, "tcp": 16, "snmp": 12, "wmi": 8}
        if hard_limits:
            base_limits.update({k: max(1, int(v)) for k, v in hard_limits.items()})
        self.hard_limits = base_limits
        self.timeout_ratio_threshold = timeout_ratio_threshold
        self.latency_spike_seconds = latency_spike_seconds

    def run(self, tasks: list[ProbeTask]) -> dict[str, Any]:
        queue_by_probe = self._build_probe_queues(tasks)
        probe_order = deque([probe for probe in PROBE_TYPES if probe in queue_by_probe or probe in self.hard_limits])

        metrics: dict[str, dict[str, Any]] = {}
        results: dict[str, list[Any]] = {}
        soft_limits: dict[str, int] = {}
        in_flight: dict[str, int] = {}
        dispatch_order: list[tuple[str, str, str]] = []
        latencies: dict[str, list[float]] = defaultdict(list)

        for probe in self.hard_limits:
            results[probe] = []
            soft_limits[probe] = self.hard_limits[probe]
            in_flight[probe] = 0
            metrics[probe] = {
                "submitted": 0,
                "completed": 0,
                "timeouts": 0,
                "backpressure_events": 0,
                "max_in_flight": 0,
                "throughput_per_second": 0.0,
                "timeout_ratio": 0.0,
                "avg_latency_seconds": 0.0,
            }

        probe_start: dict[str, float] = {probe: 0.0 for probe in self.hard_limits}
        probe_end: dict[str, float] = {probe: 0.0 for probe in self.hard_limits}

        executors = {
            probe: ThreadPoolExecutor(max_workers=self.hard_limits[probe], thread_name_prefix=f"probe-{probe}")
            for probe in self.hard_limits
        }

        futures: dict[Any, tuple[str, float]] = {}

        try:
            while self._has_pending(queue_by_probe) or futures:
                for _ in range(len(probe_order)):
                    probe = probe_order[0]
                    probe_order.rotate(-1)
                    if in_flight.get(probe, 0) >= soft_limits.get(probe, 1):
                        continue
                    task = self._pop_next_task(queue_by_probe.get(probe))
                    if task is None:
                        continue
                    if probe_start[probe] == 0.0:
                        probe_start[probe] = time.perf_counter()
                    future = executors[probe].submit(task.run)
                    futures[future] = (probe, time.perf_counter())
                    dispatch_order.append((probe, task.subnet, task.target))
                    in_flight[probe] += 1
                    metrics[probe]["submitted"] += 1
                    if in_flight[probe] > metrics[probe]["max_in_flight"]:
                        metrics[probe]["max_in_flight"] = in_flight[probe]

                if not futures:
                    continue

                done, _ = wait(list(futures.keys()), timeout=0.05, return_when=FIRST_COMPLETED)
                if not done:
                    continue

                for fut in done:
                    probe, started_at = futures.pop(fut)
                    in_flight[probe] -= 1
                    latency = time.perf_counter() - started_at
                    latencies[probe].append(latency)
                    probe_end[probe] = time.perf_counter()

                    timed_out = False
                    payload: Any = None
                    try:
                        payload = fut.result()
                    except TimeoutError:
                        timed_out = True
                    except Exception as exc:
                        payload = {"error": str(exc)}

                    if isinstance(payload, dict) and payload.get("timeout") is True:
                        timed_out = True

                    results[probe].append(payload)
                    metrics[probe]["completed"] += 1
                    if timed_out:
                        metrics[probe]["timeouts"] += 1

                    self._adapt_limit(probe, metrics[probe], soft_limits, latency, timed_out)

            for probe in metrics:
                completed = metrics[probe]["completed"]
                elapsed = 0.0
                if probe_start[probe] > 0 and probe_end[probe] >= probe_start[probe]:
                    elapsed = probe_end[probe] - probe_start[probe]
                if completed > 0 and elapsed > 0:
                    metrics[probe]["throughput_per_second"] = completed / elapsed
                if completed > 0:
                    metrics[probe]["timeout_ratio"] = metrics[probe]["timeouts"] / completed
                    metrics[probe]["avg_latency_seconds"] = sum(latencies[probe]) / len(latencies[probe])

        finally:
            for executor in executors.values():
                executor.shutdown(wait=True)

        return {
            "results": results,
            "metrics": metrics,
            "dispatch_order": dispatch_order,
            "soft_limits": soft_limits,
        }

    def _adapt_limit(
        self,
        probe: str,
        probe_metrics: dict[str, Any],
        soft_limits: dict[str, int],
        latency_seconds: float,
        timed_out: bool,
    ) -> None:
        completed = probe_metrics["completed"]
        timeout_ratio = 0.0
        if completed > 0:
            timeout_ratio = probe_metrics["timeouts"] / completed
        should_backpressure = timed_out or latency_seconds >= self.latency_spike_seconds or timeout_ratio >= self.timeout_ratio_threshold
        if should_backpressure:
            old_limit = soft_limits[probe]
            soft_limits[probe] = max(1, soft_limits[probe] - 1)
            if soft_limits[probe] != old_limit:
                probe_metrics["backpressure_events"] += 1
        elif soft_limits[probe] < self.hard_limits[probe]:
            soft_limits[probe] += 1

    def _build_probe_queues(self, tasks: list[ProbeTask]) -> dict[str, dict[str, Any]]:
        queue_by_probe: dict[str, dict[str, Any]] = {}
        per_probe_subnets: dict[str, dict[str, deque[ProbeTask]]] = defaultdict(lambda: defaultdict(deque))

        for task in tasks:
            probe = task.probe_type.lower()
            subnet = task.subnet
            per_probe_subnets[probe][subnet].append(task)

        for probe, subnet_map in per_probe_subnets.items():
            queue_by_probe[probe] = {
                "subnet_order": deque(subnet_map.keys()),
                "subnet_queues": subnet_map,
            }

        return queue_by_probe

    def _has_pending(self, queue_by_probe: dict[str, dict[str, Any]]) -> bool:
        for probe_queues in queue_by_probe.values():
            for q in probe_queues["subnet_queues"].values():
                if q:
                    return True
        return False

    def _pop_next_task(self, probe_queues: dict[str, Any] | None) -> ProbeTask | None:
        if probe_queues is None:
            return None
        subnet_order: deque[str] = probe_queues["subnet_order"]
        subnet_queues: dict[str, deque[ProbeTask]] = probe_queues["subnet_queues"]

        while subnet_order:
            subnet = subnet_order[0]
            queue = subnet_queues.get(subnet)
            if queue is None or len(queue) == 0:
                subnet_order.popleft()
                continue
            task = queue.popleft()
            subnet_order.rotate(-1)
            if len(queue) == 0:
                try:
                    subnet_order.remove(subnet)
                except ValueError:
                    pass
            return task

        return None
