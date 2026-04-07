import sqlite3
import os

DB_PATH = "data/netdocit.sqlite"

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)

def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # local interfaces detected on the host
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS interfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                ipv4 TEXT,
                ipv6 TEXT,
                mac TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        #reachable subnets and their friendly tags
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subnets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr TEXT UNIQUE NOT NULL,
                tag TEXT DEFAULT 'Unlabeled Network',
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # discovered devices across all subnets
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac TEXT UNIQUE,
                hostname TEXT,
                os TEXT,
                vendor TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # history of network scans
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                subnet_id INTEGER,
                devices_found INTEGER,
                FOREIGN KEY (subnet_id) REFERENCES subnets(id)
            )
        ''')

        # credentials for deep scanning (SNMP, etc.)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                description TEXT
            )
        ''')
        
        conn.commit()

def save_interface(iface):
    """Saves or updates an interface record."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO interfaces (name, description, ipv4, ipv6, mac, last_seen)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (iface['name'], iface['description'], iface['ipv4'], iface['ipv6'], iface['mac']))
        conn.commit()

def save_subnet(cidr, tag):
    """Saves or updates a subnet record. Updates the tag and timestamp if CIDR exists."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO subnets (cidr, tag, last_seen)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(cidr) DO UPDATE SET
                tag = excluded.tag,
                last_seen = excluded.last_seen
        ''', (cidr, tag))
        conn.commit()

def get_all_subnets():
    """Fetches all known subnets from the database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT cidr FROM subnets')
        return [row[0] for row in cursor.fetchall()]

if __name__ == "__main__":
    print(f"Checking database at {DB_PATH}...")
    init_db()
    
    subnets = get_all_subnets()
    print(f"Known Subnets: {subnets}")
