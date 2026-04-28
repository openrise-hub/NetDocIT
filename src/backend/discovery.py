import ipaddress
import time
from typing import Any
from .adaptive_scheduler import AdaptiveProbeScheduler, ProbeTask, PROBE_TYPES
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
from .protocol_depth import build_service_identity_summary

SUPPORTED_SCAN_PROFILES = {"safe", "balanced", "aggressive"}
DEFAULT_SCRIPT_TIMEOUT_SECONDS = 60
MAX_SCRIPT_TIMEOUT_SECONDS = 300


def _merge_probe_metrics(
    current: dict[str, dict[str, Any]],
    incoming: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for probe in PROBE_TYPES:
        left = current.get(probe, {})
        right = incoming.get(probe, {})

        left_completed = int(left.get("completed", 0) or 0)
        right_completed = int(right.get("completed", 0) or 0)
        total_completed = left_completed + right_completed

        left_avg = float(left.get("avg_latency_seconds", 0.0) or 0.0)
        right_avg = float(right.get("avg_latency_seconds", 0.0) or 0.0)
        weighted_avg = 0.0
        if total_completed > 0:
            weighted_avg = ((left_avg * left_completed) + (right_avg * right_completed)) / total_completed

        merged[probe] = {
            "submitted": int(left.get("submitted", 0) or 0) + int(right.get("submitted", 0) or 0),
            "completed": total_completed,
            "timeouts": int(left.get("timeouts", 0) or 0) + int(right.get("timeouts", 0) or 0),
            "backpressure_events": int(left.get("backpressure_events", 0) or 0) + int(right.get("backpressure_events", 0) or 0),
            "max_in_flight": max(int(left.get("max_in_flight", 0) or 0), int(right.get("max_in_flight", 0) or 0)),
            "throughput_per_second": float(left.get("throughput_per_second", 0.0) or 0.0)
            + float(right.get("throughput_per_second", 0.0) or 0.0),
            "timeout_ratio": (int(left.get("timeouts", 0) or 0) + int(right.get("timeouts", 0) or 0)) / total_completed
            if total_completed > 0
            else 0.0,
            "avg_latency_seconds": weighted_avg,
            "latency_p95_seconds": max(
                float(left.get("latency_p95_seconds", 0.0) or 0.0),
                float(right.get("latency_p95_seconds", 0.0) or 0.0),
            ),
            "recommended_timeout_seconds": max(
                float(left.get("recommended_timeout_seconds", 0.0) or 0.0),
                float(right.get("recommended_timeout_seconds", 0.0) or 0.0),
            ),
            "retry_attempts": int(left.get("retry_attempts", 0) or 0) + int(right.get("retry_attempts", 0) or 0),
        }

    return merged

def discover_all(
    community_override=None,
    log_fn=None,
    script_timeout_seconds=None,
    scan_profile="balanced",
    abort_signal=None,
):
    run_started_monotonic = time.monotonic()

    def log(msg):
        if log_fn: log_fn(msg)

    def persist_log(level, message, source="Scanner"):
        try:
            add_log_entry(level, message, source)
        except Exception:
            return

    def should_abort() -> bool:
        if abort_signal is None:
            return False
        if not callable(abort_signal):
            return False
        try:
            return bool(abort_signal())
        except Exception:
            return False

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
    scheduler = AdaptiveProbeScheduler()
    probe_metrics = scheduler.run([])["metrics"]
    sentinel_triggered = False
    scan_results = []

    if should_abort():
        sentinel_triggered = True
        log("Discovery aborted by sentinel signal before ping sweep.")
    else:
        icmp_run = scheduler.run(
            [
                ProbeTask(
                    "icmp",
                    "global",
                    "subnet-batch",
                    lambda: run_ps_script("ping_sweep.ps1", args=subnets, timeout_seconds=script_timeout_seconds),
                )
            ]
        )
        probe_metrics = _merge_probe_metrics(probe_metrics, icmp_run["metrics"])
        icmp_results = icmp_run["results"].get("icmp", [])
        scan_results = icmp_results[0] if icmp_results else []
    scan_error = False
    scan_error_message = None
    
    if isinstance(scan_results, dict) and "error" in scan_results:
        scan_error = True
        scan_error_message = str(scan_results.get("error"))
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
    host_enum_target_count = 0
    snmp_target_count = 0
    host_enum_result_count = 0
    snmp_result_count = 0
    if found_ips:
        host_enum_target_count = len(found_ips)
        snmp_target_count = len(found_ips)
        if should_abort():
            sentinel_triggered = True
            log("Discovery aborted by sentinel signal before host enrichment.")
        else:
            log(f"Running WMI/CIM enumeration on {len(found_ips)} hosts...")
            enrichment_run = scheduler.run(
                [
                    ProbeTask(
                        "wmi",
                        "global",
                        "host-enum-batch",
                        lambda: run_ps_script("host_enum.ps1", args=found_ips, timeout_seconds=script_timeout_seconds),
                    ),
                    ProbeTask(
                        "snmp",
                        "global",
                        "snmp-batch",
                        lambda: scan_appliances(found_ips, communities=community_override),
                    ),
                ]
            )
            probe_metrics = _merge_probe_metrics(probe_metrics, enrichment_run["metrics"])
            wmi_results = enrichment_run["results"].get("wmi", [])
            host_details = wmi_results[0] if wmi_results else []
            if isinstance(host_details, list):
                host_enum_result_count = len(_as_dict_list(host_details))
            log("Attempting SNMP credential rotation on detected hardware...")
            snmp_results = enrichment_run["results"].get("snmp", [])
            snmp_details = snmp_results[0] if snmp_results else []
            if isinstance(snmp_details, list):
                snmp_result_count = len(_as_dict_list(snmp_details))
    
    log("Generating final audit report...")
    # generate the readiness report
    report = report_readiness(interfaces, routes, subnets)
    run_finished_monotonic = time.monotonic()
    run_duration_seconds = run_finished_monotonic - run_started_monotonic
    scan_timeout_exceeded = run_duration_seconds > script_timeout_seconds
    scan_completion_state = "completed"
    scan_completion_reason = "completed_normally"
    if sentinel_triggered:
        scan_completion_state = "aborted"
        scan_completion_reason = "sentinel_triggered"
    elif scan_error:
        scan_completion_state = "scan_error"
        scan_completion_reason = "scan_script_error"
    elif scan_timeout_exceeded:
        scan_completion_state = "budget_exceeded"
        scan_completion_reason = "runtime_budget_exceeded"
    
    summary = {
        "interfaces": interfaces,
        "routes": routes,
        "subnets": report["subnets"],
        "new": report["new"],
        "missing": report["missing"],
        "priorities": report["priorities"],
        "gateways": report["gateways"],
        "scan_data": _as_dict_list(scan_results),
        "scan_error": scan_error,
        "scan_error_message": scan_error_message,
        "scan_subnet_count": scan_subnet_count,
        "responsive_endpoint_count": responsive_endpoint_count,
        "host_enum_target_count": host_enum_target_count,
        "snmp_target_count": snmp_target_count,
        "host_enum_result_count": host_enum_result_count,
        "snmp_result_count": snmp_result_count,
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
        "scan_timeout_exceeded": scan_timeout_exceeded,
        "scan_completion_state": scan_completion_state,
        "scan_completion_reason": scan_completion_reason,
        "probe_metrics": probe_metrics,
    }

    summary["host_data_count"] = len(_as_dict_list(summary["host_data"]))
    summary["snmp_data_count"] = len(_as_dict_list(summary["snmp_data"]))
    summary["service_identity"] = build_service_identity_summary(summary)

    if scan_timeout_exceeded:
        timeout_message = (
            f"Discovery exceeded its timeout budget after {run_duration_seconds:.1f}s "
            f"(limit {script_timeout_seconds}s)"
        )
        log(timeout_message)
        persist_log("WARNING", timeout_message, "Scanner")

    if sentinel_triggered:
        persist_log("WARNING", "Discovery aborted by sentinel signal.", "Scanner")
    
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
