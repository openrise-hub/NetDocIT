import re
import json
import os

# global cache for manufacturer data
OUI_MAP = {}

def load_vendors():
    global OUI_MAP
    # locate vendors.json relative to this script
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    vendor_path = os.path.join(base_dir, 'data', 'vendors.json')
    
    try:
        if os.path.exists(vendor_path):
            with open(vendor_path, 'r', encoding='utf-8') as f:
                OUI_MAP = json.load(f)
    except Exception:
        OUI_MAP = {}

# initialize on import
load_vendors()


def resolve_vendor(mac):
    """
    Resolves a MAC address to a manufacturer name using OUI prefix matching.
    """
    if not mac or mac == "Unknown":
        return "Generic"
        
    clean_mac = mac.replace("-", ":").upper()
    
    # extract the first 3 octets (OUI)
    prefix = ":".join(clean_mac.split(":")[:3])
    
    # return the mapped vendor or a generic placeholder
    return OUI_MAP.get(prefix, "Network Device")
