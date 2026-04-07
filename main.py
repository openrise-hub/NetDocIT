from src.backend.discovery import discover_all
from src.backend.processor import get_system_status
from src.backend.database import insert_devices, get_devices_sorted_by_ip, get_device_counts_by_os
from src.presentation.topology import TopologyManager
from src.presentation.exporter import MarkdownGenerator

def main():
    print("NetDocIT")
    print("=" * 40)
    
    discovery = discover_all()
    
    # seed and fetch device data for the report
    insert_devices()
    devices = get_devices_sorted_by_ip()
    dev_stats = get_device_counts_by_os()
    
    tm = TopologyManager()
    tm.build_from_discovery(discovery)
    tm.display_tui()
    
    # export interactive html map
    html_out = "topology.html"
    tm.save_html_map(html_out)
    
    # generate markdown report
    rep = MarkdownGenerator()
    rep.add_summary_section(len(discovery['subnets']), dev_stats)
    rep.add_device_table(devices)
    rep.save("REPORT.md")
    
    status = get_system_status()
    
    print("\nReadiness Report:")
    print(f"  Subnets Tracked:    {status['subnet_count']}")
    print(f"  New (Unscanned):    {status['never_scanned']}")
    print(f"  Credentials:        {'Available' if status['credentials_loaded'] else 'None'}")
    print(f"  Topology Map:       Saved to {html_out}")
    
    if status['ready_for_scan']:
        print("\nStatus: Ready for Active Scanning")
    else:
        print("\nStatus: Critical | No subnets found for scanning")

if __name__ == "__main__":
    main()
