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
        
        # Check for IPv4 not loopback
        if iface.ip and iface.ip != "127.0.0.1":
            active_ifaces.append({
                "name": iface.name,
                "description": iface.description,
                "ip": iface.ip,
                "mac": iface.mac
            })
            
    return active_ifaces

if __name__ == "__main__":
    print("Detecting active network interfaces...")
    interfaces = get_active_interfaces()
    
    for iface in interfaces:
        print(f"\nInterface: {iface['name']}")
        print(f"  Description: {iface['description']}")
        print(f"  IPv4 Address: {iface['ip']}")
        print(f"  MAC Address: {iface['mac']}")
