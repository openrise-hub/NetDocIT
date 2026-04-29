from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any


def resolve_subnet_placement(asset: dict[str, Any], subnets: list[dict[str, Any]], context: dict[str, Any]) -> dict[str, Any]:
    asset_ip = asset.get('ip')
    candidates: list[dict[str, Any]] = []

    for subnet in subnets:
        cidr = subnet.get('cidr')
        if not cidr:
            continue

        score = 0.0
        rationale: list[str] = []

        try:
            if asset_ip and ip_address(asset_ip) in ip_network(cidr, strict=False):
                score += 0.7
                rationale.append('ip_containment')
        except ValueError:
            continue

        for route in context.get('routes', []):
            network = route.get('network')
            prefix_len = route.get('prefix_len')
            if network and prefix_len and cidr == f'{network}/{prefix_len}':
                score += 0.2
                rationale.append('route_affinity')
                break

        for iface in context.get('interfaces', []):
            if iface.get('ipv4') and asset_ip and iface.get('ipv4') == asset_ip:
                score += 0.1
                rationale.append('interface_affinity')
                break

        candidates.append(
            {
                'subnet_cidr': cidr,
                'score': round(score, 3),
                'rationale': ','.join(rationale) if rationale else 'low_signal',
            }
        )

    candidates.sort(key=lambda item: (-item['score'], item['subnet_cidr']))

    if not candidates:
        return {'state': 'unplaced', 'primary': None, 'candidates': []}

    best_score = candidates[0]['score']
    top_candidates = [candidate for candidate in candidates if candidate['score'] == best_score]

    second_score = candidates[1]['score'] if len(candidates) > 1 else -1.0

    if best_score < 0.5 or len(top_candidates) > 1 or (best_score - second_score) <= 0.200001:
        return {'state': 'ambiguous', 'primary': None, 'candidates': candidates}

    return {'state': 'certain', 'primary': candidates[0], 'candidates': candidates}
