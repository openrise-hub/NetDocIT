from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures
from typing import Iterable, Callable, Any, List


class ProbeTaskRunner:
    def __init__(self, max_workers: int = 4, timeout: int = 5, retries: int = 1):
        self.max_workers = max_workers
        self.timeout = timeout
        self.retries = retries

    def _call_probe_once(self, probe_fn: Callable[[Any, Any], List[dict]], target, context):
        return probe_fn(target, context)

    def run(self, targets: Iterable, probe_fn: Callable[[Any, Any], List[dict]], context=None):
        results = []

        def worker_call(t):
            attempts = 0
            last_exc = None
            while attempts <= self.retries:
                attempts += 1
                try:
                    with ThreadPoolExecutor(max_workers=1) as exec_once:
                        fut = exec_once.submit(self._call_probe_once, probe_fn, t, context)
                        res = fut.result(timeout=self.timeout)
                    # normalize
                    if res is None:
                        res_list = []
                    elif isinstance(res, list):
                        res_list = res
                    else:
                        res_list = []

                    # annotate retry attempts when > 1
                    if attempts - 1 > 0:
                        for r in res_list:
                            if isinstance(r, dict):
                                r.setdefault("retry_attempts", attempts - 1)
                    return res_list
                except concurrent.futures.TimeoutError as te:
                    last_exc = te
                    # retry loop continues
                    continue
                except Exception as e:
                    last_exc = e
                    # retry loop continues
                    continue

            # All retries exhausted, return an error placeholder
            err = {"target": t, "error": str(last_exc) if last_exc is not None else "unknown", "retry_attempts": self.retries}
            return [err]

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {executor.submit(worker_call, t): t for t in targets}
            for fut in as_completed(future_map):
                try:
                    r = fut.result()
                    if isinstance(r, list):
                        results.extend(r)
                except Exception:
                    # protect runner from unexpected errors
                    t = future_map.get(fut)
                    results.append({"target": t, "error": "worker-failure"})

        return results
