import unittest

from src.backend.subnet_placement import resolve_subnet_placement


class TestSubnetPlacementResolver(unittest.TestCase):
    def test_direct_containment_prefers_matching_subnet(self):
        asset = {
            'canonical_asset_id': 1,
            'canonical_key': 'asset-a',
            'ip': '10.0.0.10',
            'hostname': 'srv-01',
            'vendor': 'Contoso',
        }
        subnets = [
            {'cidr': '10.0.0.0/24', 'tag': 'Office'},
            {'cidr': '10.0.1.0/24', 'tag': 'Lab'},
        ]
        context = {
            'routes': [{'network': '10.0.0.0', 'prefix_len': '24', 'interface': 'eth0', 'local_addr': '10.0.0.1'}],
            'interfaces': [{'name': 'eth0', 'ipv4': '10.0.0.1'}],
        }

        result = resolve_subnet_placement(asset, subnets, context)

        self.assertEqual(result['state'], 'certain')
        self.assertEqual(result['primary']['subnet_cidr'], '10.0.0.0/24')

    def test_close_candidates_become_ambiguous(self):
        asset = {
            'canonical_asset_id': 2,
            'canonical_key': 'asset-b',
            'ip': '10.0.0.50',
            'hostname': 'virtual-01',
            'vendor': 'Contoso',
        }
        subnets = [
            {'cidr': '10.0.0.0/24', 'tag': 'Office'},
            {'cidr': '10.0.0.0/25', 'tag': 'Office-Alt'},
        ]
        context = {
            'routes': [{'network': '10.0.0.0', 'prefix_len': '24', 'interface': 'eth0', 'local_addr': '10.0.0.1'}],
            'interfaces': [{'name': 'eth0', 'ipv4': '10.0.0.1'}],
        }

        result = resolve_subnet_placement(asset, subnets, context)

        self.assertEqual(result['state'], 'ambiguous')
        self.assertGreaterEqual(len(result['candidates']), 2)


if __name__ == '__main__':
    unittest.main()
