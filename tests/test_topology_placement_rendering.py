import unittest

from src.presentation.topology import TopologyManager


class TestTopologyPlacementRendering(unittest.TestCase):
    def test_topology_renders_primary_and_alternate_edges(self):
        discovery_summary = {
            'interfaces': [{'name': 'eth0', 'ipv4': '10.0.0.1'}],
            'routes': [{'network': '10.0.0.0', 'prefix_len': '24', 'interface': 'eth0', 'local_addr': '10.0.0.1'}],
            'subnets': [{'cidr': '10.0.0.0/24', 'tag': 'Office'}, {'cidr': '10.0.0.0/25', 'tag': 'Office-Alt'}],
            'scan_data': [],
            'host_data': [],
            'snmp_data': [],
            'asset_placements': [
                {
                    'canonical_asset_id': 1,
                    'canonical_key': 'asset-a',
                    'label': 'srv-01',
                    'primary': {'subnet_cidr': '10.0.0.0/24', 'score': 0.9, 'rationale': 'ip_containment'},
                    'alternates': [{'subnet_cidr': '10.0.0.0/25', 'score': 0.8, 'rationale': 'route_affinity'}],
                    'state': 'ambiguous',
                }
            ],
        }

        tm = TopologyManager()
        tm.build_from_discovery(discovery_summary)

        self.assertIn('asset:1', tm.graph.nodes)
        primary_edge = tm.graph.get_edge_data('subnet:10.0.0.0/24', 'asset:1')
        alternate_edge = tm.graph.get_edge_data('subnet:10.0.0.0/25', 'asset:1')

        self.assertIsNotNone(primary_edge)
        self.assertEqual(primary_edge.get('placement_kind'), 'primary')
        self.assertIsNotNone(alternate_edge)
        self.assertEqual(alternate_edge.get('placement_kind'), 'alternate')
        self.assertEqual(alternate_edge.get('style'), 'dashed')


if __name__ == '__main__':
    unittest.main()
