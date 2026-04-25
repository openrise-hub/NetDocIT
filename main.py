from backend.discovery import discover_all
from backend.processor import get_system_status
from backend.database import ingest_live_data, get_devices_sorted_by_ip, get_device_counts_by_os
from presentation.topology import TopologyManager
from presentation.exporter import MarkdownGenerator

def install_scheduler(time_str="08:00"):
    import subprocess
    import os
    import sys
    
    cwd = os.getcwd()
    task_name = "NetDocIT-DailyDiscovery"
    cmd = f'uv run netdocit scan --quiet'
    
    try:
        subprocess.run([
            "schtasks", "/create", "/tn", task_name,
            "/tr", f'cmd /c "cd /d {cwd} && {cmd}"',
            "/sc", "daily", "/st", time_str, "/f"
        ], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

QUIET = False

def q_print(msg=""):
    if not QUIET:
        print(msg)

def show_dashboard():
    if QUIET: return 'discover'
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    
    console = Console()
    console.clear()
    
    menu_text = Text()
    menu_text.append("[D]iscover ", style="bold green")
    menu_text.append("| [M]ap only ", style="bold cyan")
    menu_text.append("| [R]eport only ", style="bold yellow")
    menu_text.append("| [S]chedule daily ", style="bold magenta")
    menu_text.append("| [Q]uit", style="bold red")
    
    console.print(Panel(menu_text, title="[bold white]NetDocIT Dashboard[/bold white]", border_style="green"))
    choice = console.input("\nSelect an action: ").upper()
    
    if choice == 'S':
        time = console.input("Enter daily scan time (HH:mm) [08:00]: ")
        return f"schedule {time if time else '08:00'}"
        
    return choice

def run_discovery():
    discovery = discover_all()
    
    ingest_live_data(discovery)
    
    devices = get_devices_sorted_by_ip()
    dev_stats = get_device_counts_by_os()
    
    tm = TopologyManager()
    tm.build_from_discovery(discovery)
    
    if not QUIET:
        tm.display_tui()
    
    tm.save_html_map("topology.html")
    
    rep = MarkdownGenerator()
    rep.add_summary_section(len(discovery['subnets']), dev_stats)
    rep.add_device_table(devices)
    rep.save("REPORT.md")
    rep.save_html(len(discovery['subnets']), dev_stats, devices, "inventory.html")
    
    return discovery

from backend.database import ingest_live_data, get_devices_sorted_by_ip, get_device_counts_by_os, get_all_subnets, get_all_interfaces, get_all_routes

def run_mapping(discovery_data=None):
    if discovery_data is None:
        discovery_data = {
            "interfaces": get_all_interfaces(),
            "routes": get_all_routes(),
            "subnets": [{"cidr": c, "tag": "Stored Database"} for c in get_all_subnets()],
            "scan_data": [], "host_data": [], "snmp_data": [] # prevent build error
        }
    
    tm = TopologyManager()
    tm.build_from_discovery(discovery_data)
    
    if not QUIET:
        tm.display_tui()
        
    tm.save_html_map("topology.html")

def run_reporting():
    devices = get_devices_sorted_by_ip()
    dev_stats = get_device_counts_by_os()
    subnets = get_all_subnets()
    
    rep = MarkdownGenerator()
    rep.add_summary_section(len(subnets), dev_stats)
    rep.add_device_table(devices)
    rep.save("REPORT.md")
    rep.save_html(len(subnets), dev_stats, devices, "inventory.html")

__version__ = "0.1.0"

def main():
    import sys
    import argparse
    global QUIET
    
    parser = argparse.ArgumentParser(
        description="NetDocIT: Automated Network Inventory & Topology Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", nargs="*", 
                        help="Action to perform (D)iscover, (M)ap, (R)eport, (S)chedule")
    parser.add_argument("-v", "--version", action="version", version=f"NetDocIT v{__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="Background mode (no terminal UI)")
    parser.add_argument("-t", "--time", default="08:00", help="Time for daily schedule (HH:mm)")
    
    args = parser.parse_args()
    QUIET = args.quiet
    
    cmd_list = args.command
    choice = cmd_list[0].lower() if cmd_list else show_dashboard()
    
    sched_time = args.time
    if choice == 'schedule' and len(cmd_list) > 1:
        sched_time = cmd_list[1]
    elif choice.startswith('schedule '):
        parts = choice.split(' ')
        choice = parts[0]
        sched_time = parts[1]
    
    if choice in ['d', 'discover', 'scan', 'all']:
        discovery = run_discovery()
        run_mapping(discovery)
        run_reporting()
        q_print("\nScan and Reports successfully updated.")
    
    elif choice in ['m', 'map']:
        run_mapping()
        q_print("\nMap updated: topology.html")
        
    elif choice in ['r', 'report']:
        run_reporting()
        q_print("\nReports successfully updated: REPORT.md / inventory.html")
    
    elif choice in ['s', 'schedule']:
        if install_scheduler(sched_time):
            q_print(f"\nSuccess: Daily {sched_time} scan registered in Windows Task Scheduler.")
        else:
            q_print("\nError: Failed to register task. Ensure you have the required permissions.")
    
    elif choice == 'Q':
        q_print("Exiting.")

if __name__ == "__main__":
    main()
