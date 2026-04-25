import pysnmp.hlapi as hlapi
import json
import os

def load_config():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    config_path = os.path.join(base_dir, 'data', 'config.json')
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {"credentials": {"snmp": ["public"]}}

def query_snmp(ip, community='public'):
    oids = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysName': '1.3.6.1.2.1.1.5.0'
    }
    
    results = {'ip': ip, 'community': community}
    
    for key, oid in oids.items():
        try:
            errorIndication, errorStatus, errorIndex, varBinds = next(
                hlapi.getCmd(hlapi.SnmpEngine(),
                       hlapi.CommunityData(community),
                       hlapi.UdpTransportTarget((ip, 161), timeout=0.5, retries=0),
                       hlapi.ContextData(),
                       hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
            )
            
            if not errorIndication and not errorStatus:
                results[key] = str(varBinds[0][1])
        except Exception:
            continue
            
    return results if 'sysDescr' in results else None

def scan_appliances(ips, communities=None):
    """
    Iterates through IPs and attempts SNMP polling using a list of community strings.
    """
    if communities is None:
        config = load_config()
        communities = config.get('credentials', {}).get('snmp', ['public'])
    elif isinstance(communities, str):
        communities = [communities]

    found = []
    for ip in ips:
        # try each credential until one works
        for community in communities:
            res = query_snmp(ip, community)
            if res:
                found.append(res)
                break # stop trying other communities for this device
    return found


if __name__ == "__main__":
    print("SNMP Engine initialized.")
