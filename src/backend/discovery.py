import ipaddress
import time
from typing import Any
from .scanner import run_ps_script, get_scan_profile

def _as_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]

def get_active_interfaces(timeout_seconds=60):
    res = run_ps_script("env_discovery.ps1", timeout_seconds=timeout_seconds)
    if isinstance(res, dict):
        return _as_dict_list(res.get("interfaces", []))
    return []

def get_routing_table(timeout_seconds=60):
    res = run_ps_script("env_discovery.ps1", timeout_seconds=timeout_seconds)
    if isinstance(res, dict):
        return _as_dict_list(res.get("routes", []))
    return []

def get_subnets(routes):
    subnets = set()
    for r in routes:
        try:
            # use destination prefix directly if available
            if "prefix_len" in r:
                net = ipaddress.IPv4Network(f"{r['network']}/{r['prefix_len']}", strict=False)
            else:
                continue
                
            if net.prefixlen > 0 and net.prefixlen < 32:
                subnets.add(str(net))
        except ValueError:
            continue
    return sorted(list(subnets))

from .config_parser import load_config
from .database import init_db, save_interface, clear_interfaces, save_route, clear_routes, get_last_scans, get_all_subnets, add_log_entry
from .processor import process_discovered_subnets, get_missing_subnets, get_priority_subnets
from .snmp_engine import scan_appliances
from .vendor_lookup import resolve_vendor

SUPPORTED_SCAN_PROFILES = {"safe", "balanced", "aggressive"}
DEFAULT_SCRIPT_TIMEOUT_SECONDS = 60
MAX_SCRIPT_TIMEOUT_SECONDS = 300

def discover_all(community_override=None, log_fn=None, script_timeout_seconds=None, scan_profile="balanced"):
    run_started_monotonic = time.monotonic()

    def log(msg):
        if log_fn: log_fn(msg)

    normalized_profile = str(scan_profile or "balanced").lower()
    if normalized_profile not in SUPPORTED_SCAN_PROFILES:
        normalized_profile = "balanced"

    timeout_source = "override"
    timeout_was_sanitized = False
    if script_timeout_seconds is None:
        timeout_source = "profile"
        script_timeout_seconds = get_scan_profile(normalized_profile)["script_timeout"]

    if not isinstance(script_timeout_seconds, (int, float)) or script_timeout_seconds <= 0:
        if timeout_source == "override":
            timeout_source = "fallback"
        timeout_was_sanitized = True
        script_timeout_seconds = DEFAULT_SCRIPT_TIMEOUT_SECONDS
    if script_timeout_seconds > MAX_SCRIPT_TIMEOUT_SECONDS:
        if timeout_source == "override":
            timeout_source = "fallback"
        timeout_was_sanitized = True
        script_timeout_seconds = MAX_SCRIPT_TIMEOUT_SECONDS
    if isinstance(script_timeout_seconds, float):
        if not script_timeout_seconds.is_integer():
            timeout_was_sanitized = True
        script_timeout_seconds = int(script_timeout_seconds)
    if script_timeout_seconds < 1:
        if timeout_source == "override":
            timeout_source = "fallback"
        timeout_was_sanitized = True
        script_timeout_seconds = 1

    # unified entry point for environmental mapping
    log("Initializing local interface database...")
    clear_interfaces()
    
    log("identifying active network adapters...")
    interfaces = get_active_interfaces(timeout_seconds=script_timeout_seconds)
    for iface in interfaces:
        save_interface({
            "name": iface.get("name", "Unknown"),
            "description": iface.get("description"),
            "ipv4": iface.get("ipv4"),
            "ipv6": iface.get("ipv6"),
            "mac": iface.get("mac"),
        })
    if interfaces:
        log(f"found {len(interfaces)} adapters: {', '.join([i.get('name','') for i in interfaces])}")
    
    log("parsing os routing table...")
    clear_routes()
    routes = get_routing_table(timeout_seconds=script_timeout_seconds)
    for route in routes:
        save_route({
            "network": route.get("network"),
            "netmask": route.get("netmask"),
            "prefix_len": route.get("prefix_len"),
            "gateway": route.get("gateway"),
            "interface": route.get("interface"),
            "local_addr": route.get("local_addr"),
        })
    subnets = get_subnets(routes)
    scan_subnet_count = len(subnets)
    log(f"mapping {len(subnets)} subnets: {', '.join(subnets)}")
    
    # execute live scanning cores
    log("starting icmp ping sweep across subnets...")
    scan_results = run_ps_script("ping_sweep.ps1", args=subnets, timeout_seconds=script_timeout_seconds)
    
    if isinstance(scan_results, dict) and "error" in scan_results:
        log(f"scanner error: {scan_results['error']}")
        scan_results = []
    
    # attempt host enumeration (wmi/cim) for all found ips
    found_ips = []
    responsive_endpoint_count = 0
    if isinstance(scan_results, list):
        scan_devices = _as_dict_list(scan_results)
        responsive_endpoint_count = len(scan_devices)
        log(f"ping sweep found {len(scan_devices)} responsive endpoints.")
        # Resolve vendors for ping results
        for dev in scan_devices:
            if 'mac' in dev:
                dev['vendor'] = resolve_vendor(dev['mac'])
        found_ips = [str(dev['ip']) for dev in scan_devices if 'ip' in dev]
        
    host_details = []
    snmp_details = []
    if found_ips:
        log(f"Running WMI/CIM enumeration on {len(found_ips)} hosts...")
        host_details = run_ps_script("host_enum.ps1", args=found_ips, timeout_seconds=script_timeout_seconds)
        log("Attempting SNMP credential rotation on detected hardware...")
        snmp_details = scan_appliances(found_ips, communities=community_override)
    
    log("Generating final audit report...")
    # generate the readiness report
    report = report_readiness(interfaces, routes, subnets)
    run_finished_monotonic = time.monotonic()
    run_duration_seconds = run_finished_monotonic - run_started_monotonic
    
    summary = {
        "interfaces": interfaces,
        "routes": routes,
        "subnets": report["subnets"],
        "new": report["new"],
        "missing": report["missing"],
        "priorities": report["priorities"],
        "gateways": report["gateways"],
        "scan_data": _as_dict_list(scan_results),
        "scan_subnet_count": scan_subnet_count,
        "responsive_endpoint_count": responsive_endpoint_count,
        "host_data": host_details if isinstance(host_details, list) else [],
        "snmp_data": snmp_details,
        "scan_profile": normalized_profile,
        "script_timeout_seconds": script_timeout_seconds,
        "script_timeout_source": timeout_source,
        "script_timeout_was_sanitized": timeout_was_sanitized,
        "timeout_policy": {
            "default_seconds": DEFAULT_SCRIPT_TIMEOUT_SECONDS,
            "max_seconds": MAX_SCRIPT_TIMEOUT_SECONDS,
        },
        "run_started_monotonic": run_started_monotonic,
        "run_finished_monotonic": run_finished_monotonic,
        "run_duration_seconds": run_duration_seconds,
    }
    
    return summary

def report_readiness(interfaces, routes, subnets):
    config = load_config()
    
    # map friendly names and identify changes
    raw_subnets = []
    for sn in subnets:
        raw_subnets.append({
            "cidr": sn,
            "tag": config.get("subnet_tags", {}).get(sn, "unlabeled network")
        })
    
    # process discoveries to find brand-new or missing networks
    new_found = process_discovered_subnets(raw_subnets)
    missing = get_missing_subnets(raw_subnets)
    priorities = get_priority_subnets(raw_subnets)
    
    return {
        "interfaces": interfaces,
        "routes": routes,
        "subnets": raw_subnets,
        "new": new_found,
        "missing": missing,
        "priorities": priorities,
        "gateways": [r['gateway'] for r in routes if r['network'] == "0.0.0.0"]
    }

if __name__ == "__main__":
    print("NetDocIT Environment Discovery Engine")
    print("=" * 40)
    
    add_log_entry("info", "starting automated network discovery", "scanner")
    discovery = discover_all()
    
    print(f"Interfaces Detected: {len(discovery['interfaces'])}")
    for iface in discovery['interfaces']:
        print(f"  - {iface['name']} ({iface['ipv4'] or 'No IPv4'})")
        
    print(f"\nSubnets Identified for Scanning: {len(discovery['subnets'])}")
    for sn_obj in discovery['subnets']:
        status = " [NEW]" if sn_obj['cidr'] in discovery['new'] else ""
        print(f"  - {sn_obj['cidr']} ({sn_obj['tag']}){status}")
    
    print(f"\nScan Recommendations:")
    for tier in ["high", "medium", "low"]:
        targets = discovery['priorities'][tier]
        if targets:
            print(f"  {tier.upper()}: {', '.join(targets)}")
        
    if discovery['missing']:
        print(f"\nMissing Networks (Offline): {len(discovery['missing'])}")
        for sn in discovery['missing']:
            print(f"  - {sn}")

    if discovery['gateways']:
        print(f"\nDefault Gateway: {discovery['gateways'][0]}")
