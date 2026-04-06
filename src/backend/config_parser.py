import json
import os

def load_config(config_path="data/config.json"):
    """
    Loads the configuration.
    Returns an empty dictionary if the file is missing or unreadable.
    """
    if not os.path.exists(config_path):
        return {}
    
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
            
    except (json.JSONDecodeError, IOError):
        return {}

if __name__ == "__main__":
    print("Testing Supplemental Config Loader...")
    config = load_config()
    
    print("\nLoaded Credentials (SNMP):")
    print(config.get("credentials", {}).get("snmp", []))
    
    print("\nSubnet Tags Mapping:")
    print(config.get("subnet_tags", {}))
    
    print("\nScan Exclusions:")
    print(config.get("exclusions", []))
