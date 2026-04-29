import unittest
from src.backend import discovery

class FakeProbe:
    called = False

    @staticmethod
    def probe(target, context):
        FakeProbe.called = True
        return []

class TestSchedulerUDPOrchestration(unittest.TestCase):
    def test_scheduler_invokes_udp_probes(self):
        run = discovery.run_scan_with_probes(targets=[('192.0.2.1', 53)], probe_impl=FakeProbe.probe)
        self.assertTrue(FakeProbe.called)

if __name__ == '__main__':
    unittest.main()
