from src.backend.discovery import discover_all
from src.backend.processor import get_system_status
from src.backend.database import insert_devices, get_devices_sorted_by_ip, get_device_counts_by_os
from src.presentation.topology import TopologyManager
from src.presentation.exporter import MarkdownGenerator

from src.presentation.exporter import MarkdownGenerator

def show_dashboard():
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

def main():
    choice = show_dashboard()
    
    if choice == 'D':
        discovery = run_discovery()
        status = get_system_status()
        
        print("\nReadiness Report:")
        print(f"  Subnets Tracked:    {status['subnet_count']}")
        print(f"  New (Unscanned):    {status['never_scanned']}")
        print(f"  Credentials:        {'Available' if status['credentials_loaded'] else 'None'}")
        print(f"  Topology Map:       Saved to topology.html")
    
    elif choice == 'Q':
        print("Exiting NetDocIT.")

if __name__ == "__main__":
    main()
