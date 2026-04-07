import scapy.all as scapy

def get_active_interfaces():
    """
    Identifies all active IPv4 network interfaces on the host.
    Returns a list of interface objects with their IP addresses.
    """
    active_ifaces = []
    
    # scapy's conf.ifaces stores all detected interfaces on the system
    # filter for those that have a valid IPv4 address and are not loopback
    for iface_name in scapy.conf.ifaces:
        iface = scapy.conf.ifaces[iface_name]
        
        # check for any valid IP (v4 or v6) and exclude loopbacks
        has_ipv4 = iface.ip and iface.ip != "127.0.0.1"
        has_ipv6 = hasattr(iface, 'ip6') and iface.ip6 and iface.ip6 != "::1"

        if has_ipv4 or has_ipv6:
            active_ifaces.append({
                "name": iface.name,
                "description": iface.description,
                "ipv4": iface.ip if has_ipv4 else None,
                "ipv6": iface.ip6 if has_ipv6 else None,
                "mac": iface.mac
            })
            
    return active_ifaces

def get_routing_table():
    """
    Extracts the OS routing table to identify default gateways and specific routes.
    Returns a list of route objects.
    """
    routes = []
    
    # scapy's conf.route contains the parsed IPv4 routing table
    for network, netmask, gateway, iface_name, local_addr, metric in scapy.conf.route.routes:
        if local_addr != "127.0.0.1":
            routes.append({
                "network": scapy.ltoa(network),
                "netmask": scapy.ltoa(netmask),
                "gateway": gateway,
                "interface": iface_name,
                "local_addr": local_addr,
                "metric": metric
            })
            
    return routes

import ipaddress

def get_subnets(routes):
    subnets = set()
    for r in routes:
        try:
            # create a network object from the IP and mask
            net = ipaddress.IPv4Network(f"{r['network']}/{r['netmask']}", strict=False)
            
            # exclude default route (0.0.0.0/0) and host routes (/32)
            if net.prefixlen > 0 and net.prefixlen < 32:
                subnets.add(str(net))
        except ValueError:
            continue
            
    return sorted(list(subnets))

from .config_parser import load_config
from .database import init_db, save_interface
from .processor import process_discovered_subnets, get_missing_subnets

def discover_all():
    init_db()
    
    interfaces = get_active_interfaces()
    routes = get_routing_table()
    subnets = get_subnets(routes)
    config = load_config()
    
    # save each detected interface to the database
    for iface in interfaces:
        save_interface(iface)
    
    # map friendly names and identify changes
    raw_subnets = []
    for sn in subnets:
        raw_subnets.append({
            "cidr": sn,
            "tag": config.get("subnet_tags", {}).get(sn, "Unlabeled Network")
        })
    
    # process discovers to find brand-new or missing networks
    new_found = process_discovered_subnets(raw_subnets)
    missing = get_missing_subnets(raw_subnets)
    
    return {
        "interfaces": interfaces,
        "routes": routes,
        "subnets": raw_subnets,
        "new": new_found,
        "missing": missing,
        "gateways": [r['gateway'] for r in routes if r['network'] == "0.0.0.0"]
    }

if __name__ == "__main__":
    print("NetDocIT Environment Discovery Engine")
    print("=" * 40)
    
    discovery = discover_all()
    
    print(f"Interfaces Detected: {len(discovery['interfaces'])}")
    for iface in discovery['interfaces']:
        print(f"  - {iface['name']} ({iface['ipv4'] or 'No IPv4'})")
        
    print(f"\nSubnets Identified for Scanning: {len(discovery['subnets'])}")
    for sn_obj in discovery['subnets']:
        status = " [NEW]" if sn_obj['cidr'] in discovery['new'] else ""
        print(f"  - {sn_obj['cidr']} ({sn_obj['tag']}){status}")
        
    if discovery['missing']:
        print(f"\nMissing Networks (Offline): {len(discovery['missing'])}")
        for sn in discovery['missing']:
            print(f"  - {sn}")

    if discovery['gateways']:
        print(f"\nDefault Gateway: {discovery['gateways'][0]}")
