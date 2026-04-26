import sqlite3
import os
import ipaddress
from contextlib import contextmanager

DB_PATH = "data/netdocit.sqlite"

@contextmanager
def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()

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

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT NOT NULL,
                netmask TEXT,
                prefix_len TEXT,
                gateway TEXT,
                interface TEXT,
                local_addr TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
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
        # logs for auditing scans and errors
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                level TEXT,
                message TEXT,
                source TEXT
            )
        ''')
        
        conn.commit()

def add_log_entry(level, message, source="System"):
    """Adds a persistent log entry to the database."""
    normalized_level = str(level).upper()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO logs (level, message, source)
            VALUES (?, ?, ?)
        ''', (normalized_level, message, source))
        conn.commit()

def get_logs(limit=50):
    """Retrieves the latest logs from storage."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, level, message, source FROM logs ORDER BY timestamp DESC LIMIT ?', (limit,))
        return cursor.fetchall()

def clear_logs():
    """Wipes all log entries."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM logs')
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
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT cidr FROM subnets')
        return [row[0] for row in cursor.fetchall()]

def get_last_scans():
    """Returns the latest scan timestamp for each known subnet."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT s.cidr, MAX(sc.timestamp)
            FROM subnets s
            LEFT JOIN scans sc ON s.id = sc.subnet_id
            GROUP BY s.cidr
        ''')
        return {row[0]: row[1] for row in cursor.fetchall()}

def get_all_interfaces():
    # fetch all local host interfaces from storage
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT name, description, ipv4, ipv6, mac FROM interfaces')
        return [{"name": r[0], "description": r[1], "ipv4": r[2], "ipv6": r[3], "mac": r[4]} for r in cursor.fetchall()]

def get_all_routes():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT network, netmask, prefix_len, gateway, interface, local_addr FROM routes')
        return [
            {
                "network": r[0],
                "netmask": r[1],
                "prefix_len": r[2],
                "gateway": r[3],
                "interface": r[4],
                "local_addr": r[5],
            }
            for r in cursor.fetchall()
        ]


def save_route(route):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO routes (network, netmask, prefix_len, gateway, interface, local_addr, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            route.get('network'),
            route.get('netmask'),
            route.get('prefix_len'),
            route.get('gateway'),
            route.get('interface'),
            route.get('local_addr'),
        ))
        conn.commit()

def clear_interfaces():
    """Clears out old network adapters to start a fresh scan."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM interfaces')
        conn.commit()


def clear_routes():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM routes')
        conn.commit()

def ingest_live_data(summary):
    """Parses live scan, cim, and snmp data and inserts it into the database."""
    devices_map = {}
    
    # base network scan (ping sweep & arp)
    for dev in summary.get('scan_data', []):
        devices_map[dev['ip']] = {
            "ip": dev['ip'],
            "mac": dev.get('mac', 'Unknown'),
            "hostname": dev.get('hostname', 'Active-Host'),
            "os": dev.get('os', 'Unknown'),
            "vendor": dev.get('vendor', 'Detected-Live')
        }
        
    # add Windows WMI/CIM enumeration details
    for host in summary.get('host_data', []):
        ip = host['ip']
        if ip in devices_map:
            devices_map[ip]["hostname"] = host.get("hostname", devices_map[ip]["hostname"])
            devices_map[ip]["os"] = host.get("os", devices_map[ip]["os"])
            devices_map[ip]["vendor"] = host.get("vendor", devices_map[ip]["vendor"])
            
    # add generic SNMP appliance details
    for snmp in summary.get('snmp_data', []):
        ip = snmp['ip']
        if ip in devices_map:
            devices_map[ip]["hostname"] = snmp.get("sysName", devices_map[ip]["hostname"])
            devices_map[ip]["os"] = snmp.get("sysDescr", devices_map[ip]["os"])
            # if we found a vendor via SNMP (rare but possible), update it
            if 'vendor' in snmp:
                devices_map[ip]["vendor"] = snmp['vendor']
            
    # insert unified data into storage
    devices_tuples = [
        (d["ip"], d["mac"], d["hostname"], d["os"], d["vendor"])
        for d in devices_map.values()
    ]
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM devices')
        
        cursor.executemany('''
            INSERT OR IGNORE INTO devices (ip, mac, hostname, os, vendor)
            VALUES (?, ?, ?, ?, ?)
        ''', devices_tuples)
        conn.commit()

def get_devices_sorted_by_ip():
    # fetch all devices sorted numerically by IP
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT ip, mac, hostname, os, vendor FROM devices')
        rows = cursor.fetchall()

    def sort_key(row):
        ip = row[0]
        try:
            return (0, ipaddress.ip_address(ip))
        except ValueError:
            return (1, ip)

    return sorted(rows, key=sort_key)

def get_device_counts_by_os():
    # count windows hosts vs network appliances
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                SUM(CASE WHEN os LIKE "%Windows%" THEN 1 ELSE 0 END) as windows_count,
                SUM(CASE WHEN os NOT LIKE "%Windows%" THEN 1 ELSE 0 END) as appliance_count
            FROM devices
        ''')
        row = cursor.fetchone()
        return {"windows": row[0] or 0, "appliances": row[1] or 0}

if __name__ == "__main__":
    print(f"Checking database at {DB_PATH}...")
    init_db()
    
    subnets = get_all_subnets()
    print(f"Known Subnets: {subnets}")
    
    scans = get_last_scans()
    print(f"Latest Scans: {scans}")
