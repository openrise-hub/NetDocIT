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

if __name__ == "__main__":
    print("Detecting active network interfaces (IPv4/IPv6)...")
    interfaces = get_active_interfaces()
    
    for iface in interfaces:
        print(f"\nInterface: {iface['name']}")
        print(f"  Description: {iface['description']}")
        if iface['ipv4']: print(f"  IPv4 Address: {iface['ipv4']}")
        if iface['ipv6']: print(f"  IPv6 Address: {iface['ipv6']}")
        print(f"  MAC Address: {iface['mac']}")
