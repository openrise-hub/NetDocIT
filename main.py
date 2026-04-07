from src.backend.discovery import discover_all
from src.backend.processor import get_system_status
from src.backend.database import insert_devices, get_devices_sorted_by_ip, get_device_counts_by_os
from src.presentation.topology import TopologyManager
from src.presentation.exporter import MarkdownGenerator

from src.presentation.exporter import MarkdownGenerator

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
    menu_text.append("| [Q]uit", style="bold red")
    
    console.print(Panel(menu_text, title="[bold white]NetDocIT Dashboard[/bold white]", border_style="green"))
    choice = console.input("\nSelect an action: ").upper()
    return choice

def run_discovery():
    discovery = discover_all()
    
    # seed and fetch device data for the report
    insert_devices()
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

from src.backend.database import insert_devices, get_devices_sorted_by_ip, get_device_counts_by_os, get_all_subnets, get_all_interfaces, get_all_routes

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

def main():
    import sys
    import argparse
    global QUIET
    
    parser = argparse.ArgumentParser(description="NetDocIT Terminal Dashboard")
    parser.add_argument("command", nargs="?", choices=["discover", "report", "map", "all"], help="Subcommand to run")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress terminal output")
    args = parser.parse_args()
    
    QUIET = args.quiet
    
    # if no command is passed, launch the interactive dashboard
    choice = args.command if args.command else show_dashboard()
    
    if choice in ['D', 'discover', 'all']:
        discovery = run_discovery()
        run_mapping(discovery)
        run_reporting()
        q_print("\nDiscovery and Reports updated.")
    
    elif choice in ['M', 'map']:
        run_mapping()
        q_print("\nMap updated: topology.html")
        
    elif choice in ['R', 'report']:
        run_reporting()
        q_print("\nReports updated: REPORT.md / inventory.html")
    
    elif choice == 'Q':
        q_print("Exiting.")

if __name__ == "__main__":
    main()
