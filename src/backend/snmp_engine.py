import pysnmp.hlapi as hlapi

def query_snmp(ip, community='public'):
    oids = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysName': '1.3.6.1.2.1.1.5.0'
    }
    
    results = {'ip': ip}
    
    for key, oid in oids.items():
        errorIndication, errorStatus, errorIndex, varBinds = next(
            hlapi.getCmd(hlapi.SnmpEngine(),
                   hlapi.CommunityData(community),
                   hlapi.UdpTransportTarget((ip, 161), timeout=1, retries=0),
                   hlapi.ContextData(),
                   hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
        )
        
        if not errorIndication and not errorStatus:
            results[key] = str(varBinds[0][1])
            
    return results if 'sysDescr' in results else None

def scan_appliances(ips, community='public'):
    # iterate through ips and attempt snmp polling
    found = []
    for ip in ips:
        res = query_snmp(ip, community)
        if res:
            found.append(res)
    return found

if __name__ == "__main__":
    print("SNMP Engine initialized.")
