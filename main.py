from src.backend.discovery import discover_all
from src.backend.processor import get_system_status
from src.presentation.topology import TopologyManager

def main():
    print("NetDocIT")
    print("=" * 40)
    
    discovery = discover_all()
    
    tm = TopologyManager()
    tm.build_from_discovery(discovery)
    tm.display_tui()
    
    status = get_system_status()
    
    print("\nReadiness Report:")
    print(f"  Subnets Tracked:    {status['subnet_count']}")
    print(f"  New (Unscanned):    {status['never_scanned']}")
    print(f"  Credentials:        {'Available' if status['credentials_loaded'] else 'None'}")
    
    if status['ready_for_scan']:
        print("\nStatus: Ready for Active Scanning")
    else:
        print("\nStatus: Critical | No subnets found for scanning")

if __name__ == "__main__":
    main()
