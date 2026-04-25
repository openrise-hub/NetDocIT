import sqlite3
import os

_CONN = None

def init_db():
    global _CONN
    if _CONN is not None:
        return
        
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    db_path = os.path.join(base_dir, 'data', 'vendors.sqlite')
    
    if os.path.exists(db_path):
        _CONN = sqlite3.connect(db_path, check_same_thread=False)

def resolve_vendor(mac):
    """
    Resolves a MAC address to a manufacturer name using the local SQLite database.
    """
    if not mac or mac == "Unknown":
        return "Generic"
        
    init_db()
    if _CONN is None:
        return "Network Device"

    # Normalize MAC and extract OUI prefix (e.g., 000C29)
    clean_mac = mac.replace("-", "").replace(":", "").upper()
    prefix = clean_mac[:6]
    
    try:
        cursor = _CONN.cursor()
        cursor.execute("SELECT name FROM vendors WHERE prefix = ?", (prefix,))
        result = cursor.fetchone()
        if result:
            return result[0]
    except Exception:
        pass
            
    return "Network Device"

