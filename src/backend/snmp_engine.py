try:
    import pysnmp.hlapi as hlapi  # pyright: ignore[reportMissingImports]
except Exception:
    hlapi = None
from typing import Any, cast

from .config_parser import load_config as load_base_config
from .secrets import resolve_snmp_credentials

def query_snmp(ip, community='public'):
    oids = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysName': '1.3.6.1.2.1.1.5.0'
    }
    
    results = {'ip': ip}
    hl = cast(Any, hlapi)
    
    for key, oid in oids.items():
        try:
            errorIndication, errorStatus, errorIndex, varBinds = next(
                  hl.getCmd(hl.SnmpEngine(),
                      hl.CommunityData(community),
                      hl.UdpTransportTarget((ip, 161), timeout=0.5, retries=0),
                      hl.ContextData(),
                      hl.ObjectType(hl.ObjectIdentity(oid)))
            )
            
            if not errorIndication and not errorStatus:
                results[key] = str(varBinds[0][1])
        except Exception:
            continue

    # build a basic explainability summary if we have sysDescr
    if 'sysDescr' in results:
        descr = results.get('sysDescr', '')
        why = f"SNMP sysDescr contains: {descr[:80]}" if descr else "sysDescr present"
        how = f"snmp_engine.query_snmp(community={community})->oids(sysDescr,sysName)"
        confidence = 0.5
        lowerv = descr.lower()
        if any(k in lowerv for k in ('cisco', 'juniper', 'arista', 'huawei', 'mikrotik')):
            confidence = 0.9
        elif len(descr) > 10:
            confidence = 0.75
        results['explainability'] = {'why': why, 'how': how, 'confidence': confidence}

    return results if 'sysDescr' in results else None

def scan_appliances(ips, communities=None):
    """
    Iterates through IPs and attempts SNMP polling using a list of community strings.
    """
    if communities is None:
        config = load_base_config()
        communities, _ = resolve_snmp_credentials(override=None, config=config)
    elif isinstance(communities, str):
        communities = [communities]

    found = []
    for ip in ips:
        # try each credential until one works
        for community in communities:
            res = query_snmp(ip, community)
            if res:
                # ensure we do not expose community strings in returned payloads
                if 'community' in res:
                    del res['community']
                # if the query didn't build explainability, synthesize a minimal one here
                if 'explainability' not in res:
                    descr = res.get('sysDescr', '')
                    why = f"SNMP sysDescr contains: {descr[:80]}" if descr else "sysDescr present"
                    how = f"snmp_engine.query_snmp(community={community})"
                    confidence = 0.5
                    lowerv = (descr or '').lower()
                    if any(k in lowerv for k in ('cisco', 'juniper', 'arista', 'huawei', 'mikrotik')):
                        confidence = 0.9
                    elif len(descr or '') > 10:
                        confidence = 0.75
                    res['explainability'] = {'why': why, 'how': how, 'confidence': confidence}
                # normalize explainability shape
                expl = res.get('explainability') or {}
                res['explainability'] = {
                    'why': expl.get('why'),
                    'how': expl.get('how'),
                    'confidence': expl.get('confidence', 0.0),
                }
                found.append(res)
                break # stop trying other communities for this device
    return found


if __name__ == "__main__":
    print("SNMP Engine initialized.")
