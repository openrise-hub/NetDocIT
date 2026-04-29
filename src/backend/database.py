import sqlite3
import os
import ipaddress
import json
import time
from contextlib import contextmanager

from .asset_identity import resolve_canonical_asset

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
            CREATE TABLE IF NOT EXISTS canonical_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                canonical_key TEXT UNIQUE NOT NULL,
                preferred_label TEXT,
                primary_mac TEXT,
                primary_vendor TEXT,
                primary_hostname TEXT,
                confidence REAL DEFAULT 0.0,
                conflict_state TEXT DEFAULT 'resolved',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS asset_aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                canonical_asset_id INTEGER NOT NULL,
                alias_type TEXT NOT NULL,
                alias_value TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (canonical_asset_id, alias_type, alias_value),
                FOREIGN KEY (canonical_asset_id) REFERENCES canonical_assets(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS asset_sightings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                canonical_asset_id INTEGER,
                sighting_key TEXT UNIQUE NOT NULL,
                ip TEXT,
                mac TEXT,
                hostname TEXT,
                vendor TEXT,
                source TEXT,
                payload_json TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (canonical_asset_id) REFERENCES canonical_assets(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS identity_conflicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sighting_key TEXT UNIQUE NOT NULL,
                conflict_reason TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
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
            CREATE TABLE IF NOT EXISTS probe_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id TEXT NOT NULL,
                probe_type TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                hostname TEXT,
                os TEXT,
                vendor TEXT,
                payload_json TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_probe_observations_scan_probe
            ON probe_observations (scan_run_id, probe_type)
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

def upsert_canonical_asset(canonical_key, preferred_label=None, primary_mac=None, primary_vendor=None, primary_hostname=None, confidence=0.0, conflict_state='resolved'):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO canonical_assets (
                canonical_key, preferred_label, primary_mac, primary_vendor, primary_hostname, confidence, conflict_state, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(canonical_key) DO UPDATE SET
                preferred_label = excluded.preferred_label,
                primary_mac = COALESCE(excluded.primary_mac, canonical_assets.primary_mac),
                primary_vendor = COALESCE(excluded.primary_vendor, canonical_assets.primary_vendor),
                primary_hostname = COALESCE(excluded.primary_hostname, canonical_assets.primary_hostname),
                confidence = MAX(canonical_assets.confidence, excluded.confidence),
                conflict_state = excluded.conflict_state,
                updated_at = CURRENT_TIMESTAMP
        ''', (canonical_key, preferred_label, primary_mac, primary_vendor, primary_hostname, confidence, conflict_state))
        conn.commit()

def add_asset_alias(canonical_asset_id, alias_type, alias_value):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO asset_aliases (canonical_asset_id, alias_type, alias_value)
            VALUES (?, ?, ?)
            ON CONFLICT(canonical_asset_id, alias_type, alias_value) DO NOTHING
        ''', (canonical_asset_id, alias_type, alias_value))
        conn.commit()

def add_asset_sighting(canonical_asset_id, sighting_key, ip, mac, hostname, vendor, source, payload_json):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO asset_sightings (
                canonical_asset_id, sighting_key, ip, mac, hostname, vendor, source, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sighting_key) DO UPDATE SET
                canonical_asset_id = excluded.canonical_asset_id,
                ip = excluded.ip,
                mac = excluded.mac,
                hostname = excluded.hostname,
                vendor = excluded.vendor,
                source = excluded.source,
                payload_json = excluded.payload_json
        ''', (canonical_asset_id, sighting_key, ip, mac, hostname, vendor, source, payload_json))
        conn.commit()

def add_identity_conflict(sighting_key, conflict_reason, evidence_json):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO identity_conflicts (sighting_key, conflict_reason, evidence_json)
            VALUES (?, ?, ?)
            ON CONFLICT(sighting_key) DO UPDATE SET
                conflict_reason = excluded.conflict_reason,
                evidence_json = excluded.evidence_json
        ''', (sighting_key, conflict_reason, evidence_json))
        conn.commit()

def _canonical_sightings(summary):
    sightings_by_key = {}

    def merge_sighting(key, source, ip, mac, hostname, vendor, payload):
        normalized_key = str(key or ip or payload.get('target') or payload.get('hostname') or payload.get('sysName') or payload.get('mac') or 'unknown')
        current = sightings_by_key.get(normalized_key)
        if current is None:
            sightings_by_key[normalized_key] = {
                'source': source,
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor,
                'payload': payload,
            }
            return

        if not current.get('ip') and ip:
            current['ip'] = ip
        if not current.get('mac') and mac:
            current['mac'] = mac
        if not current.get('hostname') and hostname:
            current['hostname'] = hostname
        if not current.get('vendor') and vendor:
            current['vendor'] = vendor
        current['payload'] = payload
        current['source'] = source if current.get('source') == 'probe' else current['source']

    for dev in summary.get('scan_data', []):
        if not isinstance(dev, dict):
            continue
        merge_sighting(dev.get('ip'), 'icmp', dev.get('ip'), dev.get('mac'), dev.get('hostname'), dev.get('vendor'), dev)

    for host in summary.get('host_data', []):
        if not isinstance(host, dict):
            continue
        merge_sighting(host.get('ip'), 'wmi', host.get('ip'), host.get('mac'), host.get('hostname'), host.get('vendor'), host)

    for snmp in summary.get('snmp_data', []):
        if not isinstance(snmp, dict):
            continue
        merge_sighting(snmp.get('ip'), 'snmp', snmp.get('ip'), snmp.get('mac'), snmp.get('sysName') or snmp.get('hostname'), snmp.get('vendor'), snmp)

    for observation in summary.get('probe_observations', []):
        if not isinstance(observation, dict):
            continue
        merge_sighting(
            observation.get('ip') or observation.get('target'),
            str(observation.get('source') or observation.get('service_hint') or observation.get('probe_type') or 'probe'),
            observation.get('ip') or observation.get('target'),
            observation.get('mac'),
            observation.get('hostname') or observation.get('sysName'),
            observation.get('vendor'),
            observation,
        )

    return list(sightings_by_key.values())


def ingest_canonical_assets(summary):
    sightings = _canonical_sightings(summary)
    if not sightings:
        return 0

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT canonical_key, preferred_label, primary_mac, primary_vendor, primary_hostname, confidence, conflict_state FROM canonical_assets'
        )
        existing_assets = [
            {
                'canonical_key': row[0],
                'preferred_label': row[1],
                'primary_mac': row[2],
                'primary_vendor': row[3],
                'primary_hostname': row[4],
                'confidence': row[5],
                'conflict_state': row[6],
            }
            for row in cursor.fetchall()
        ]

    existing_by_key = {asset['canonical_key']: asset for asset in existing_assets}

    for sighting in sightings:
        sighting_key = json.dumps(sighting['payload'], separators=(',', ':'), sort_keys=True)
        resolution = resolve_canonical_asset(sighting, existing_assets)

        if resolution['state'] == 'conflict':
            add_identity_conflict(sighting_key, resolution['conflict_reason'], json.dumps(sighting['payload'], separators=(',', ':'), sort_keys=True))
            add_asset_sighting(None, sighting_key, sighting.get('ip'), sighting.get('mac'), sighting.get('hostname'), sighting.get('vendor'), sighting.get('source'), json.dumps(sighting['payload'], separators=(',', ':'), sort_keys=True))
            continue

        canonical_key = resolution['canonical_key']
        matched_asset = existing_by_key.get(canonical_key, {})
        preferred_label = matched_asset.get('preferred_label') or sighting.get('hostname') or sighting.get('ip')
        primary_mac = matched_asset.get('primary_mac') or sighting.get('mac')
        primary_vendor = matched_asset.get('primary_vendor') or sighting.get('vendor')
        primary_hostname = matched_asset.get('primary_hostname') or sighting.get('hostname')

        upsert_canonical_asset(
            canonical_key,
            preferred_label=preferred_label,
            primary_mac=primary_mac,
            primary_vendor=primary_vendor,
            primary_hostname=primary_hostname,
            confidence=resolution['confidence'],
            conflict_state='resolved',
        )

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM canonical_assets WHERE canonical_key = ?', (canonical_key,))
            canonical_asset_id = cursor.fetchone()[0]

        add_asset_sighting(
            canonical_asset_id,
            sighting_key,
            sighting.get('ip'),
            sighting.get('mac'),
            sighting.get('hostname'),
            sighting.get('vendor'),
            sighting.get('source'),
            json.dumps(sighting['payload'], separators=(',', ':'), sort_keys=True),
        )
        for alias_type, alias_value in (
            ('mac', sighting.get('mac')),
            ('hostname', sighting.get('hostname')),
            ('vendor', sighting.get('vendor')),
        ):
            if alias_value:
                add_asset_alias(canonical_asset_id, alias_type, alias_value)

        existing_by_key[canonical_key] = {
            'canonical_key': canonical_key,
            'preferred_label': preferred_label,
            'primary_mac': primary_mac,
            'primary_vendor': primary_vendor,
            'primary_hostname': primary_hostname,
            'confidence': resolution['confidence'],
            'conflict_state': 'resolved',
        }
        if not any(asset['canonical_key'] == canonical_key for asset in existing_assets):
            existing_assets.append(existing_by_key[canonical_key])

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM devices')
        cursor.execute('SELECT id, canonical_key, preferred_label, primary_mac, primary_hostname, primary_vendor FROM canonical_assets')
        rows = cursor.fetchall()
        devices_tuples = []
        for canonical_asset_id, canonical_key, preferred_label, primary_mac, primary_hostname, primary_vendor in rows:
            cursor.execute(
                'SELECT ip FROM asset_sightings WHERE canonical_asset_id = ? AND ip IS NOT NULL ORDER BY id DESC LIMIT 1',
                (canonical_asset_id,),
            )
            sighting_row = cursor.fetchone()
            ip = sighting_row[0] if sighting_row else canonical_key
            devices_tuples.append(
                (
                    ip,
                    primary_mac,
                    preferred_label or primary_hostname or ip,
                    'Unknown',
                    primary_vendor,
                )
            )
        cursor.executemany(
            '''
            INSERT OR IGNORE INTO devices (ip, mac, hostname, os, vendor)
            VALUES (?, ?, ?, ?, ?)
            ''',
            devices_tuples,
        )
        conn.commit()

    return len(sightings)

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

def _observation_rows(summary, scan_run_id):
    rows = []

    for dev in summary.get('scan_data', []):
        rows.append((
            scan_run_id,
            'icmp',
            dev.get('ip'),
            dev.get('mac'),
            dev.get('hostname'),
            dev.get('os'),
            dev.get('vendor'),
            json.dumps(dev, separators=(',', ':'), sort_keys=True),
        ))

    for host in summary.get('host_data', []):
        rows.append((
            scan_run_id,
            'wmi',
            host.get('ip'),
            host.get('mac'),
            host.get('hostname'),
            host.get('os'),
            host.get('vendor'),
            json.dumps(host, separators=(',', ':'), sort_keys=True),
        ))

    for snmp in summary.get('snmp_data', []):
        rows.append((
            scan_run_id,
            'snmp',
            snmp.get('ip'),
            snmp.get('mac'),
            snmp.get('sysName'),
            snmp.get('sysDescr'),
            snmp.get('vendor'),
            json.dumps(snmp, separators=(',', ':'), sort_keys=True),
        ))

    for observation in summary.get('probe_observations', []):
        if not isinstance(observation, dict):
            continue
        probe_type = observation.get('service_hint') or observation.get('probe_type') or 'probe'
        target = observation.get('target') or observation.get('ip')
        rows.append((
            scan_run_id,
            str(probe_type),
            target,
            observation.get('mac'),
            observation.get('hostname'),
            observation.get('os'),
            observation.get('vendor'),
            json.dumps(observation, separators=(',', ':'), sort_keys=True),
        ))

    return rows

def persist_probe_observations(summary, scan_run_id=None, batch_size=200):
    effective_run_id = str(scan_run_id or summary.get('scan_run_id') or f"scan-{time.time_ns()}")
    effective_batch_size = max(1, int(batch_size))
    rows = _observation_rows(summary, effective_run_id)

    if not rows:
        return effective_run_id, 0

    with get_db_connection() as conn:
        cursor = conn.cursor()
        for offset in range(0, len(rows), effective_batch_size):
            chunk = rows[offset:offset + effective_batch_size]
            cursor.executemany('''
                INSERT INTO probe_observations (
                    scan_run_id,
                    probe_type,
                    ip,
                    mac,
                    hostname,
                    os,
                    vendor,
                    payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', chunk)
        conn.commit()

    return effective_run_id, len(rows)

def ingest_live_data(summary):
    """Parses live scan, cim, and snmp data and inserts it into the database."""
    scan_run_id, observation_count = persist_probe_observations(summary)

    if summary.get('scan_completion_state') == 'aborted':
        return {
            'scan_run_id': scan_run_id,
            'observation_count': observation_count,
            'resolved_host_count': 0,
            'resolved_state_updated': False,
        }

    resolved_host_count = ingest_canonical_assets(summary)
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        conn.commit()

    return {
        'scan_run_id': scan_run_id,
        'observation_count': observation_count,
        'resolved_host_count': resolved_host_count,
        'resolved_state_updated': True,
    }

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
