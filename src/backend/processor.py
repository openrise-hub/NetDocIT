from .database import get_all_subnets, save_subnet, get_last_scans
from .config_parser import load_config

def process_discovered_subnets(discovered):
    """
    Identifies new subnets and updates existing ones in the database.
    """
    existing = set(get_all_subnets())
    new_networks = []
    
    for sn in discovered:
        cidr = sn['cidr']
        tag = sn['tag']
        
        if cidr not in existing:
            new_networks.append(cidr)
            
        save_subnet(cidr, tag)
        
    return new_networks

def get_missing_subnets(discovered):
    """
    Identifies subnets that were previously known but are not in the current scan.
    """
    discovered_cidrs = {sn['cidr'] for sn in discovered}
    existing_cidrs = set(get_all_subnets())
    
    return list(existing_cidrs - discovered_cidrs)

def get_system_status():
    # summary of scan readiness
    config = load_config()
    subnets = get_all_subnets()
    last_scans = get_last_scans()
    
    # check scan based on networks and config
    has_subnets = len(subnets) > 0
    has_creds = len(config.get("credentials", {}).get("snmp", [])) > 0
    
    return {
        "subnet_count": len(subnets),
        "never_scanned": list(last_scans.values()).count(None),
        "credentials_loaded": has_creds,
        "ready_for_scan": has_subnets
    }

if __name__ == "__main__":
    # todo(Andrick): discovery collection
    temp_discovery = [
        {"cidr": "192.168.1.0/24", "tag": "Main Office"},
        {"cidr": "10.0.0.0/8", "tag": "Data Center"}
    ]
    
    brand_new = process_discovered_subnets(temp_discovery)
    print(f"New networks: {brand_new}")
