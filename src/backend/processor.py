from datetime import datetime, timedelta
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

def get_priority_subnets(discovered):
    config = load_config()
    interval = config.get("scan_interval_hours", 24)
    
    last_scans = get_last_scans()
    now = datetime.now()
    threshold = now - timedelta(hours=interval)
    
    priorities = {"high": [], "medium": [], "low": []}
    
    for sn in discovered:
        cidr = sn['cidr']
        last_scan_str = last_scans.get(cidr)
        
        if last_scan_str is None:
            priorities["high"].append(cidr)
        else:
            try:
                # sqlite stores timestamps as strings
                last_scan_dt = datetime.fromisoformat(last_scan_str)
                if last_scan_dt < threshold:
                    priorities["medium"].append(cidr)
                else:
                    priorities["low"].append(cidr)
            except (ValueError, TypeError):
                priorities["high"].append(cidr)
                
    return priorities

def get_system_status():
    """Returns a summary of the current network inventory and scan readiness."""
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
    
    prios = get_priority_subnets(temp_discovery)
    print(f"Scan Priorities: {prios}")
