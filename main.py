from src.backend.discovery import discover_all
from src.backend.processor import get_system_status
from src.backend.database import ingest_live_data, get_devices_sorted_by_ip, get_device_counts_by_os
from src.presentation.topology import TopologyManager
from src.presentation.exporter import MarkdownGenerator

def install_scheduler():
    import subprocess
    import os
    
    # get current directory and command
    cwd = os.getcwd()
    task_name = "NetDocIT-DailyDiscovery"
    cmd = f'uv run netdocit discover --quiet'
    
    # execute windows schtasks to register the daily 8am scan
    # /sc daily /st 08:00 /f (force overwrite)
    try:
        subprocess.run([
            "schtasks", "/create", "/tn", task_name,
            "/tr", f'cmd /c "cd /d {cwd} && {cmd}"',
            "/sc", "daily", "/st", "08:00", "/f"
        ], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

QUIET = False

def q_print(msg=""):
    if not QUIET:
        print(msg)

def show_dashboard():
    if QUIET: return 'discover' # default to full discovery in quiet mode
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    
    console = Console()
    console.clear()
    
    # build the interactive dashboard
    menu_text = Text()
    menu_text.append("[D]iscover ", style="bold green")
    menu_text.append("| [M]ap only ", style="bold cyan")
    menu_text.append("| [R]eport only ", style="bold yellow")
    menu_text.append("| [S]chedule daily ", style="bold magenta")
    menu_text.append("| [Q]uit", style="bold red")
    
    console.print(Panel(menu_text, title="[bold white]NetDocIT Dashboard[/bold white]", border_style="green"))
    choice = console.input("\nSelect an action: ").upper()
    return choice

def run_discovery():
    discovery = discover_all()
    
    # ingest live scan data into the database
    ingest_live_data(discovery)
    
    devices = get_devices_sorted_by_ip()
    dev_stats = get_device_counts_by_os()
    
    tm = TopologyManager()
    tm.build_from_discovery(discovery)
    
    if not QUIET:
        tm.display_tui()
    
    # export interactive html map
    html_out = "topology.html"
    tm.save_html_map(html_out)
    
    # generate markdown report
    rep = MarkdownGenerator()
    rep.add_summary_section(len(discovery['subnets']), dev_stats)
    rep.add_device_table(devices)
    rep.save("REPORT.md")
    
    # generate html inventory dashboard
    rep.save_html(len(discovery['subnets']), dev_stats, devices, "inventory.html")
    
    return discovery

from src.backend.database import ingest_live_data, get_devices_sorted_by_ip, get_device_counts_by_os, get_all_subnets, get_all_interfaces, get_all_routes

def run_mapping(discovery_data=None):
    # build and display topology map
    if discovery_data is None:
        # fetch data from storage if not provided by a fresh scan
        discovery_data = {
            "interfaces": get_all_interfaces(),
            "routes": get_all_routes(),
            "subnets": [{"cidr": c, "tag": "Stored Database"} for c in get_all_subnets()]
        }
    
    tm = TopologyManager()
    tm.build_from_discovery(discovery_data)
    
    if not QUIET:
        tm.display_tui()
        
    tm.save_html_map("topology.html")

def run_reporting():
    # generate reports from existing storage
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
    parser.add_argument("command", nargs="?", 
                        choices=["scan", "discover", "report", "map", "schedule", "all"], 
                        help="Action to perform (default: launch dashboard)")
    parser.add_argument("-v", "--version", action="version", version=f"NetDocIT v{__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="Background mode (no terminal UI)")
    
    args = parser.parse_args()
    
    QUIET = args.quiet
    
    # if no command is passed, launch the interactive dashboard
    choice = args.command if args.command else show_dashboard()
    
    if choice in ['D', 'discover', 'scan', 'all']:
        discovery = run_discovery()
        run_mapping(discovery)
        run_reporting()
        q_print("\nScan and Reports successfully updated.")
    
    elif choice in ['M', 'map']:
        run_mapping()
        q_print("\nMap updated: topology.html")
        
    elif choice in ['R', 'report']:
        run_reporting()
        q_print("\nReports updated: REPORT.md / inventory.html")
    
    elif choice == 'S':
        if install_scheduler():
            q_print("\nSuccess: Daily 08:00 AM scan registered in Task Scheduler.")
        else:
            q_print("\nError: Failed to register task. Ensure you have the required permissions.")
    
    elif choice == 'Q':
        q_print("Exiting.")

if __name__ == "__main__":
    main()
