import unittest
from src.backend.probe_runner import ProbeTaskRunner

def noop_probe(target, ctx):
    return [{'target': target, 'service': 'dns', 'confidence': 0.9}]

class TestProbeRunner(unittest.TestCase):
    def test_runs_probes_concurrently(self):
        runner = ProbeTaskRunner(max_workers=2, timeout=2)
        results = runner.run([('192.0.2.1', 53), ('192.0.2.2', 161)], noop_probe)
        self.assertEqual(len(results), 2)

if __name__ == '__main__':
    unittest.main()
