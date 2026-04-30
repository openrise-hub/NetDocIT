from src.backend import snmp_engine


def test_snmp_explainability_monkeypatch(monkeypatch):
    # Monkeypatch query_snmp to simulate a device returning sysDescr
    def fake_query(ip, community='public'):
        return {'ip': ip, 'sysDescr': 'Cisco IOS Software, C3750', 'sysName': 'switch1'}

    monkeypatch.setattr(snmp_engine, 'query_snmp', fake_query)

    results = snmp_engine.scan_appliances(['192.0.2.5'], communities=['public'])
    assert isinstance(results, list) and len(results) == 1
    item = results[0]
    assert 'explainability' in item
    expl = item['explainability']
    assert expl['why'].startswith('SNMP sysDescr contains')
    assert 'snmp_engine.query_snmp' in expl['how']
    assert expl['confidence'] >= 0.75
