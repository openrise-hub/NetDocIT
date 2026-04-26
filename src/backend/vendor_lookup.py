import sqlite3
import os

_CONN = None


def _get_vendor_db_path():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base_dir, 'data', 'vendors.sqlite')

def init_db():
    db_path = _get_vendor_db_path()
    if os.path.exists(db_path):
        with sqlite3.connect(db_path):
            return

def resolve_vendor(mac):
    """
    Resolves a MAC address to a manufacturer name using the local SQLite database.
    """
    if not mac or mac == "Unknown":
        return "Generic"

    db_path = _get_vendor_db_path()
    if not os.path.exists(db_path):
        return "Network Device"

    # Normalize MAC and extract OUI prefix (e.g., 000C29)
    clean_mac = mac.replace("-", "").replace(":", "").upper()
    prefix = clean_mac[:6]
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM vendors WHERE prefix = ?", (prefix,))
            result = cursor.fetchone()
            if result:
                return result[0]
    except Exception:
        pass
            
    return "Network Device"

