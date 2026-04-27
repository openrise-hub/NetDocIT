from .backend.discovery import discover_all
from .backend.processor import get_system_status
from .backend.database import ingest_live_data, get_devices_sorted_by_ip, get_device_counts_by_os
from .presentation.topology import TopologyManager
from .presentation.exporter import MarkdownGenerator
from .presentation.tui import DashboardApp


def is_admin():
    try:
        import ctypes
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return False
        return windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return False


def install_scheduler(time_str="08:00", profile="balanced", timeout_seconds=None):
    import subprocess
    import os

    if not is_admin():
        return "E_ADMIN"

    cwd = os.getcwd()
    task_name = "NetDocIT-DailyDiscovery"
    cmd = f'uv run netdocit scan --quiet --profile {profile}'
    if timeout_seconds is not None:
        cmd += f' --timeout {timeout_seconds:g}'

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
    if QUIET:
        return "discover"
    app = DashboardApp()
    app.console.clear()
    app.console.print(app.render())

    choice = app.console.input("\n[bold cyan]Command > [/bold cyan]").lower()

    if choice == 's':
        time = app.console.input("Enter daily scan time (HH:mm) [08:00]: ")
        return f"schedule {time if time else '08:00'}"

    return choice


def run_discovery(app=None, community=None, scan_profile="balanced", script_timeout_seconds=None):
    from .backend.database import add_log_entry
    add_log_entry("INFO", "Starting automated network discovery", "Scanner")

    if app:
        app.state = "SCANNING"

    discovery = discover_all(
        community_override=community,
        log_fn=app.add_log if app else None,
        scan_profile=scan_profile,
        script_timeout_seconds=script_timeout_seconds,
    )

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

    add_log_entry("INFO", f"Discovery finished. Found {len(devices)} devices.", "Scanner")

    if app:
        app.state = "MENU"

    return discovery


from .backend.database import ingest_live_data, get_devices_sorted_by_ip, get_device_counts_by_os, get_all_subnets, get_all_interfaces, get_all_routes


def run_mapping(discovery_data=None):
    if discovery_data is None:
        discovery_data = {
            "interfaces": get_all_interfaces(),
            "routes": get_all_routes(),
            "subnets": [{"cidr": c, "tag": "Stored Database"} for c in get_all_subnets()],
            "scan_data": [], "host_data": [], "snmp_data": []
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

import time

try:
    import msvcrt
except ModuleNotFoundError:
    class _MsvcrtShim:
        @staticmethod
        def kbhit():
            return False

        @staticmethod
        def getch():
            return b""

    msvcrt = _MsvcrtShim()


def get_key():
    kbhit = getattr(msvcrt, "kbhit", None)
    getch = getattr(msvcrt, "getch", None)
    if callable(kbhit) and callable(getch) and kbhit():
        try:
            raw = getch()
            if isinstance(raw, (bytes, bytearray)):
                return raw.decode('utf-8').lower()
            return None
        except Exception:
            return None
    return None


def main():
    import sys
    import argparse
    from .backend.database import init_db

    init_db()

    global QUIET

    parser = argparse.ArgumentParser(
        description="NetDocIT: Automated Network Inventory & Topology Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", nargs="*",
                        help="Action to perform (D)iscover, (M)ap, (R)eport, (L)ogs, (S)chedule")
    parser.add_argument("-v", "--version", action="version", version=f"NetDocIT v{__version__}")
    parser.add_argument("-q", "--quiet", "--silent", action="store_true", dest="quiet", help="Background mode")
    parser.add_argument("-t", "--time", default="08:00", help="Time for daily schedule (HH:mm)")
    parser.add_argument("--timeout", type=float, help="Script timeout override in seconds")
    parser.add_argument("-c", "--community", help="SNMP community string override")
    parser.add_argument("-p", "--profile", choices=["safe", "balanced", "aggressive"], default="balanced", help="Scan profile")

    args = parser.parse_args()
    QUIET = args.quiet

    if QUIET:
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    cmd_list = args.command

    if not cmd_list:
        from rich.live import Live
        import threading
        app = DashboardApp()
        try:
            with Live(app, console=app.console, screen=True, auto_refresh=True, refresh_per_second=10):
                while True:
                    kbhit = getattr(msvcrt, "kbhit", None)
                    getch = getattr(msvcrt, "getch", None)
                    if callable(kbhit) and callable(getch) and kbhit():
                        try:
                            res = getch()
                            if isinstance(res, (bytes, bytearray)):
                                key = res.decode('utf-8').lower()
                            else:
                                key = None
                        except UnicodeDecodeError:
                            key = None

                        if key == 'q':
                            break
                        elif key == '1' and app.state != "SCANNING":
                            app.state = "SCANNING"

                            def run():
                                try:
                                    d = run_discovery(
                                        app=app,
                                        community=args.community,
                                        scan_profile=args.profile,
                                        script_timeout_seconds=args.timeout,
                                    )
                                    run_mapping(d)
                                    run_reporting()
                                except Exception as exc:
                                    from .backend.database import add_log_entry
                                    add_log_entry("ERROR", f"Discovery workflow failed: {exc}", "Scanner")
                                    app.add_log(f"[ERROR] Discovery workflow failed: {exc}")
                                finally:
                                    app.state = "MENU"

                            threading.Thread(target=run, daemon=True).start()
                        elif key == '2':
                            app.state = "INVENTORY"
                            app.devices = get_devices_sorted_by_ip()
                            app.scroll_index = 0
                        elif key == 'w' and app.state == "INVENTORY":
                            app.scroll_index = max(0, app.scroll_index - 5)
                        elif key == 's' and app.state == "INVENTORY":
                            if app.scroll_index + 20 < len(app.devices):
                                app.scroll_index += 5
                        elif key == '3':
                            from .backend.database import get_logs
                            app.state = "LOGS"
                            logs = get_logs(20)
                            app.log_buffer = [f"[{l}] {m}" for t, l, m, s in reversed(logs)]
                        elif key == '\x1b':
                            app.state = "MENU"
                    time.sleep(0.05)
        except KeyboardInterrupt:
            pass
        return

    choice = cmd_list[0].lower()
    sched_time = args.time
    if choice == 'schedule' and len(cmd_list) > 1:
        sched_time = cmd_list[1]
    elif choice.startswith('schedule '):
        parts = choice.split(' ')
        choice = parts[0]
        sched_time = parts[1]

    if choice in ['d', 'discover', 'scan', 'all', '1']:
        from rich.live import Live
        app = DashboardApp()
        try:
            with Live(app.render(), console=app.console, screen=True) as live:
                discovery = run_discovery(
                    app=app,
                    community=args.community,
                    scan_profile=args.profile,
                    script_timeout_seconds=args.timeout,
                )
                live.update(app.render())
                run_mapping(discovery)
                run_reporting()
            q_print("\nScan and Reports successfully updated.")
        except KeyboardInterrupt:
            q_print("\n[bold yellow]Scan cancelled by user.[/bold yellow]")
            return

    elif choice in ['m', 'map']:
        run_mapping()
        q_print("\nMap updated: topology.html")

    elif choice in ['r', 'report', '2']:
        run_reporting()
        q_print("\nReports successfully updated: REPORT.md / inventory.html")

    elif choice in ['l', 'logs', 'L', '3']:
        from .backend.database import get_logs, clear_logs
        from rich.console import Console
        from rich.table import Table

        if "clear" in sys.argv:
            clear_logs()
            q_print("\nLogs cleared.")
            return

        logs = get_logs(50)
        if not logs:
            q_print("\nNo logs found.")
            return

        console = Console()
        table = Table(title="System Logs (Last 50)")
        table.add_column("Timestamp", style="dim")
        table.add_column("Level")
        table.add_column("Message")
        table.add_column("Source")

        for ts, lvl, msg, src in logs:
            table.add_row(ts, lvl, msg, src)
        console.print(table)

    elif choice in ['s', 'schedule']:
        if args.timeout is None:
            result = install_scheduler(sched_time, profile=args.profile)
        else:
            result = install_scheduler(sched_time, profile=args.profile, timeout_seconds=args.timeout)
        if result is True:
            q_print(f"\nSuccess: Daily {sched_time} scan registered in Windows Task Scheduler.")
        elif result == "E_ADMIN":
            q_print("\n[BOLD RED]ACCESS DENIED:[/BOLD RED] You must run this command from an Administrator terminal (Elevated) to register a background task.")
        else:
            q_print("\nError: Failed to register task. Check your permissions or system configuration.")

    elif choice == 'Q':
        q_print("Exiting.")


if __name__ == "__main__":
    main()
