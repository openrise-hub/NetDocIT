from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console, Group
from datetime import datetime
from rich.table import Table
from rich.text import Text

class DashboardApp:
    def __init__(self):
        self.layout = Layout()
        self.console = Console()
        self.state = "MENU"
        self.log_buffer = [] 
        self.devices = [] # current session hosts
        self.live_scan_devices = []
        self.live_scan_phase = "idle"
        self.live_scan_counts = {"found": 0, "enriched": 0}
        self.live_scan_selected_index = 0
        self.live_scan_sort_mode = "newest"
        self.live_scan_filter_mode = "all"
        self._live_scan_sequence = 0
        self.last_discovery_summary = None
        self.scroll_index = 0 # position for table windowing
        self._init_layout()

    def add_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_buffer.append(f"[dim]{timestamp}[/dim] {message}")
        if len(self.log_buffer) > 100:
            self.log_buffer.pop(0)

    def _live_device_key(self, device):
        if isinstance(device, dict):
            return str(device.get("ip") or device.get("hostname") or device.get("mac") or "")
        return str(device)

    def _live_confidence(self, device):
        if not isinstance(device, dict):
            return 0.0
        explainability = device.get("explainability")
        if isinstance(explainability, dict):
            confidence = explainability.get("confidence")
            if isinstance(confidence, (int, float)):
                return float(confidence)
        confidence = device.get("confidence")
        if isinstance(confidence, (int, float)):
            return float(confidence)
        return 0.0

    def _live_device_label(self, device):
        if not isinstance(device, dict):
            return "unknown"
        hostname = device.get("hostname") or device.get("sysName") or "unknown"
        vendor = device.get("vendor") or "unknown"
        return f"{hostname} · {vendor}"

    def _live_device_sources(self, device):
        if not isinstance(device, dict):
            return []
        sources = device.get("_live_sources")
        if isinstance(sources, list):
            return sources
        return []

    def _merge_live_device(self, item, source_tag):
        if not isinstance(item, dict):
            return
        if not self._scan_device_is_valid(item):
            return
        ip = item.get("ip")
        if not ip:
            return
        existing = next((device for device in self.live_scan_devices if device.get("ip") == ip), None)
        if existing is None:
            merged = dict(item)
            self._live_scan_sequence += 1
            merged["_live_first_seen"] = self._live_scan_sequence
            merged["_live_last_seen"] = self._live_scan_sequence
            merged["_live_update_count"] = 1
            merged["_live_sources"] = [source_tag]
            self.live_scan_devices.append(merged)
        else:
            existing.update(item)
            self._live_scan_sequence += 1
            existing["_live_last_seen"] = self._live_scan_sequence
            existing["_live_update_count"] = int(existing.get("_live_update_count", 1) or 1) + 1
            sources = existing.get("_live_sources")
            if not isinstance(sources, list):
                sources = []
            if source_tag not in sources:
                sources.append(source_tag)
            existing["_live_sources"] = sources

    def _live_visible_devices(self):
        devices = [device for device in self.live_scan_devices if isinstance(device, dict)]
        if self.live_scan_filter_mode == "fresh":
            devices = [device for device in devices if int(device.get("_live_update_count", 1) or 1) == 1]

        if self.live_scan_sort_mode == "ip":
            devices.sort(key=lambda device: str(device.get("ip") or ""))
        elif self.live_scan_sort_mode == "hostname":
            devices.sort(key=lambda device: str(device.get("hostname") or device.get("sysName") or ""))
        elif self.live_scan_sort_mode == "confidence":
            devices.sort(key=lambda device: self._live_confidence(device), reverse=True)
        else:
            devices.sort(key=lambda device: int(device.get("_live_first_seen", 0) or 0), reverse=True)

        return devices

    def _selected_live_device(self):
        visible_devices = self._live_visible_devices()
        if not visible_devices:
            return None, visible_devices
        if self.live_scan_selected_index >= len(visible_devices):
            self.live_scan_selected_index = len(visible_devices) - 1
        if self.live_scan_selected_index < 0:
            self.live_scan_selected_index = 0
        return visible_devices[self.live_scan_selected_index], visible_devices

    def move_live_selection(self, delta):
        visible_devices = self._live_visible_devices()
        if not visible_devices:
            self.live_scan_selected_index = 0
            return
        self.live_scan_selected_index = max(0, min(len(visible_devices) - 1, self.live_scan_selected_index + delta))

    def cycle_live_sort_mode(self):
        modes = ["newest", "ip", "hostname", "confidence"]
        current = modes.index(self.live_scan_sort_mode) if self.live_scan_sort_mode in modes else 0
        self.live_scan_sort_mode = modes[(current + 1) % len(modes)]
        self.live_scan_selected_index = 0

    def toggle_live_filter_mode(self):
        self.live_scan_filter_mode = "fresh" if self.live_scan_filter_mode == "all" else "all"
        self.live_scan_selected_index = 0

    def _live_summary_line(self):
        return (
            f"phase: {self.live_scan_phase} | {self.live_scan_counts['found']} found | {self.live_scan_counts['enriched']} enriched | "
            f"sort: {self.live_scan_sort_mode} | filter: {self.live_scan_filter_mode}"
        )

    def _scan_status_text(self):
        completion_state = None
        timeout_seconds = None
        if isinstance(self.last_discovery_summary, dict):
            completion_state = self.last_discovery_summary.get("scan_completion_state")
            timeout_seconds = self.last_discovery_summary.get("script_timeout_seconds")

        budget_label = "budget: live"
        if completion_state == "budget_exceeded":
            budget_label = f"budget: exceeded ({timeout_seconds}s limit)"
        elif completion_state == "aborted":
            budget_label = "budget: aborted"
        elif completion_state == "scan_error":
            budget_label = "budget: scan error"
        elif completion_state == "completed":
            budget_label = "budget: completed"

        return (
            f"[bold yellow]Phase:[/bold yellow] {self.live_scan_phase}    "
            f"[bold green]Found:[/bold green] {self.live_scan_counts['found']}    "
            f"[bold magenta]Enriched:[/bold magenta] {self.live_scan_counts['enriched']}    "
            f"[bold cyan]Sort:[/bold cyan] {self.live_scan_sort_mode}    "
            f"[bold cyan]Filter:[/bold cyan] {self.live_scan_filter_mode}    "
            f"[bold red]{budget_label}[/bold red]"
        )

    def _selected_device_detail_text(self, device):
        if not device:
            return "Waiting for devices..."
        provenance = {}
        if isinstance(self.last_discovery_summary, dict):
            provenance = self.last_discovery_summary.get("provenance") or {}
        explainability = device.get("explainability") if isinstance(device, dict) else {}
        lines = [
            f"[bold]IP:[/bold] {device.get('ip', 'unknown')}",
            f"[bold]Hostname:[/bold] {device.get('hostname') or device.get('sysName') or 'unknown'}",
            f"[bold]Vendor:[/bold] {device.get('vendor') or 'unknown'}",
            f"[bold]OS:[/bold] {device.get('os') or 'unknown'}",
            f"[bold]Confidence:[/bold] {self._live_confidence(device):.2f}",
            f"[bold]Seen:[/bold] first {device.get('_live_first_seen', 0)} / updates {device.get('_live_update_count', 0)}",
            f"[bold]Sources:[/bold] {', '.join(self._live_device_sources(device)) or 'scan'}",
        ]
        if isinstance(explainability, dict) and explainability:
            lines.append("")
            lines.append("[bold]Device Evidence[/bold]")
            why = explainability.get("why") or "unknown"
            how = explainability.get("how") or "unknown"
            lines.append(f"[dim]Why:[/dim] {why}")
            lines.append(f"[dim]How:[/dim] {how}")

        tcp_scan = {}
        if isinstance(self.last_discovery_summary, dict):
            tcp_scan = self.last_discovery_summary.get("tcp_port_scan_data") or {}
        ip = device.get("ip")
        host_ports = tcp_scan.get(ip, []) if ip else []
        open_entries = [e for e in host_ports if isinstance(e, dict) and e.get("open")]
        if open_entries:
            from ..backend.transports.fingerprint import PORT_SERVICE_MAP
            lines.append("")
            lines.append("[bold]Open TCP Ports[/bold]")
            for entry in sorted(open_entries, key=lambda e: e.get("port", 0)):
                port = entry.get("port")
                svc = PORT_SERVICE_MAP.get(port, "")
                banner = entry.get("banner")
                rtt = entry.get("rtt_ms")
                if banner:
                    first_line = (banner or "").split("\n")[0].strip()[:60]
                    lines.append(f"[dim]{port}[/dim]/{svc}  {first_line}")
                else:
                    rtt_str = f" {rtt}ms" if rtt else ""
                    lines.append(f"[dim]{port}[/dim]/{svc}{rtt_str}")
        if isinstance(provenance, dict) and provenance:
            lines.append("")
            lines.append("[bold]Run Provenance[/bold]")
            collector = provenance.get("collector", {})
            source = provenance.get("source", {})
            lines.append(f"[dim]Collector:[/dim] {collector.get('name', 'unknown')} {collector.get('version', '')}".rstrip())
            lines.append(f"[dim]Source:[/dim] {source.get('module', 'unknown')}.{source.get('function', 'unknown')}")
            fingerprint = provenance.get("credential_audit_summary", {}).get("cred_fingerprint")
            if fingerprint:
                lines.append(f"[dim]Credential fingerprint:[/dim] {fingerprint[:12]}...")
        return "\n".join(lines)

    def _scan_device_is_valid(self, device):
        if not isinstance(device, dict):
            return False
        ip = device.get("ip")
        if not isinstance(ip, str) or not ip:
            return False
        try:
            import ipaddress

            ip_addr = ipaddress.IPv4Address(ip)
        except Exception:
            return False
        return not (
            ip_addr.is_multicast
            or ip_addr.is_loopback
            or ip_addr.is_unspecified
            or ip_addr.is_reserved
            or ip_addr.is_link_local
        )

    def apply_scan_event(self, event, payload=None):
        payload = payload or {}
        if event == "phase":
            self.live_scan_phase = str(payload.get("state", "running"))
            self.add_log(f"[bold cyan]{self.live_scan_phase.replace('_', ' ')}[/bold cyan]")
            return

        if event == "scan_targets_found":
            targets = payload.get("targets", [])
            if isinstance(targets, list):
                for target in targets:
                    self._merge_live_device(target, "icmp")
            self.live_scan_counts["found"] = len(self._live_visible_devices())
            self.scroll_index = 0
            self.live_scan_selected_index = 0
            self.add_log(f"[bold green]found {self.live_scan_counts['found']} responsive endpoints[/bold green]")
            return

        if event == "host_details_ready":
            host_data = payload.get("host_data", [])
            snmp_data = payload.get("snmp_data", [])
            if isinstance(host_data, list):
                for item in host_data:
                    self._merge_live_device(item, "wmi")
            if isinstance(snmp_data, list):
                for item in snmp_data:
                    self._merge_live_device(item, "snmp")
            self.live_scan_counts["enriched"] = len(self._live_visible_devices())
            self.add_log(f"[bold magenta]enriched {self.live_scan_counts['enriched']} assets[/bold magenta]")
            return

        if event == "scan_completed":
            summary = payload.get("summary")
            if isinstance(summary, dict):
                self.last_discovery_summary = summary
                self.devices = summary.get("snmp_data") or summary.get("host_data") or self.live_scan_devices
            self.live_scan_phase = "completed"
            self.add_log("[bold green]scan completed[/bold green]")

    def make_live_scan_view(self):
        selected_device, _ = self._selected_live_device()
        layout = Layout()
        layout.split_column(Layout(name="status", size=3), Layout(name="content", ratio=1))
        layout["content"].split_row(Layout(name="findings", ratio=3), Layout(name="details", ratio=2))
        layout["status"].update(Panel(self._scan_status_text(), title="Scan Status", border_style="magenta"))
        left = Panel(self._make_live_scan_list(), title="Findings", border_style="yellow")
        right = Panel(self._selected_device_detail_text(selected_device), title="Host Details", border_style="cyan")
        layout["findings"].update(left)
        layout["details"].update(right)
        return layout

    def _make_live_scan_list(self):
        table = Table(box=None, expand=True)
        table.add_column("#", width=3)
        table.add_column("IP", style="bold cyan")
        table.add_column("Host / Vendor", overflow="fold")
        table.add_column("State", width=12)

        visible_devices = self._live_visible_devices()
        if not visible_devices:
            return Group(
                Text.from_markup("[dim]No live findings yet.[/dim]"),
                Text.from_markup(f"[dim]{self._live_summary_line()}[/dim]"),
            )

        if self.live_scan_selected_index >= len(visible_devices):
            self.live_scan_selected_index = len(visible_devices) - 1

        for index, device in enumerate(visible_devices[:20]):
            selected = index == self.live_scan_selected_index
            selected_marker = ">" if selected else " "
            label = self._live_device_label(device)
            conf = self._live_confidence(device)
            state = f"{conf:.2f}"
            if int(device.get("_live_update_count", 1) or 1) > 1:
                state = f"{state} +"

            # color rows by confidence: high=green, med=yellow, low=red
            if conf >= 0.80:
                row_color = "green"
            elif conf >= 0.50:
                row_color = "yellow"
            else:
                row_color = "red"

            row_style = f"{row_color}"
            if selected:
                row_style = f"reverse {row_style}"

            table.add_row(selected_marker, str(device.get("ip", "?.?.?.?")), label, state, style=row_style)

        return Group(
            Text.from_markup(f"[bold]{self._live_summary_line()}[/bold]"),
            Text(),
            table,
        )

    def handle_scanning_key(self, key):
        if key in ("w", "up"):
            self.move_live_selection(-1)
        elif key in ("s", "down"):
            self.move_live_selection(1)
        elif key == "n":
            self.cycle_live_sort_mode()
        elif key == "f":
            self.toggle_live_filter_mode()
        elif key == "c":
            self.copy_ip_of_selected()
        elif key == "i":
            self.jump_selected_to_inventory()
        elif key == "m":
            self.copy_mac_of_selected()

    def copy_ip_of_selected(self):
        """Copy the selected device IP to the system clipboard (best-effort)."""
        device, _ = self._selected_live_device()
        if not device:
            self.add_log("[dim]No device selected to copy[/dim]")
            return
        ip = device.get("ip")
        if not ip:
            self.add_log("[dim]Selected device has no IP[/dim]")
            return
        try:
            import pyperclip
            pyperclip.copy(ip)
            self.add_log(f"[bold]copied {ip} to clipboard[/bold]")
            return
        except Exception:
            pass
        try:
            import subprocess, sys
            if sys.platform.startswith("win"):
                p = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
                p.communicate(input=ip.encode("utf-8"))
                self.add_log(f"[bold]copied {ip} to clipboard[/bold]")
                return
            elif sys.platform.startswith("linux"):
                p = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
                p.communicate(input=ip.encode("utf-8"))
                self.add_log(f"[bold]copied {ip} to clipboard[/bold]")
                return
        except Exception:
            self.add_log(f"[dim]unable to copy to clipboard: {ip}[/dim]")

    def jump_selected_to_inventory(self):
        """Switch to inventory view and attempt to focus the selected device."""
        device, _ = self._selected_live_device()
        if not device:
            self.add_log("[dim]No device selected to jump to inventory[/dim]")
            return
        ip = device.get("ip")
        if not ip:
            self.add_log("[dim]Selected device has no IP[/dim]")
            return
        # try to find in existing devices
        for idx, dev in enumerate(self.devices):
            if isinstance(dev, dict) and dev.get("ip") == ip:
                self.state = "INVENTORY"
                # position a few rows before the found device for context
                self.scroll_index = max(0, idx - 2)
                self.add_log(f"[bold cyan]jumped to inventory: {ip}[/bold cyan]")
                return
        # not found: add to the top of inventory and jump
        self.devices.insert(0, device)
        self.state = "INVENTORY"
        self.scroll_index = 0
        self.add_log(f"[bold cyan]added and jumped to inventory: {ip}[/bold cyan]")

    def copy_mac_of_selected(self):
        """Copy the selected device MAC address to the system clipboard (best-effort)."""
        device, _ = self._selected_live_device()
        if not device:
            self.add_log("[dim]No device selected to copy MAC[/dim]")
            return
        mac = device.get("mac") or device.get("hwaddr") or device.get("mac_address")
        if not mac:
            self.add_log("[dim]Selected device has no MAC[/dim]")
            return
        mac_str = str(mac)
        try:
            import pyperclip
            pyperclip.copy(mac_str)
            self.add_log(f"[bold]copied {mac_str} to clipboard[/bold]")
            return
        except Exception:
            pass
        try:
            import subprocess, sys
            if sys.platform.startswith("win"):
                p = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
                p.communicate(input=mac_str.encode("utf-8"))
                self.add_log(f"[bold]copied {mac_str} to clipboard[/bold]")
                return
            elif sys.platform.startswith("linux"):
                p = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
                p.communicate(input=mac_str.encode("utf-8"))
                self.add_log(f"[bold]copied {mac_str} to clipboard[/bold]")
                return
        except Exception:
            self.add_log(f"[dim]unable to copy to clipboard: {mac_str}[/dim]")

    def _init_layout(self):
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=1)
        )
        self.layout["body"].split_row(
            Layout(name="sidebar", size=25),
            Layout(name="main", ratio=1)
        )

    def make_header(self):
        time_str = datetime.now().strftime("%H:%M:%S")
        status = "[bold green]IDLE[/bold green]"
        if self.state == "SCANNING":
            status = "[bold blink yellow]SCANNING[/bold blink yellow]"
        elif self.state == "INVENTORY":
            status = "[bold cyan]INVENTORY[/bold cyan]"
        elif self.state == "LOGS":
            status = "[bold blue]AUDIT[/bold blue]"
        elif self.last_discovery_summary and self.last_discovery_summary.get("scan_completion_state") == "budget_exceeded":
            status = "[bold red]OVER BUDGET[/bold red]"
            
        return Panel(
            Layout(
                f" [bold cyan]NetDocIT[/bold cyan] | {status} "
            ),
            title=f"[dim]{time_str}[/dim]",
            title_align="right",
            style="white on blue"
        )

    def make_sidebar(self):
        menu = f"{'[reverse]' if self.state == 'MENU' else ''}[bold green]1.[/bold green] Start Discovery\n"
        menu += f"{'[reverse]' if self.state == 'INVENTORY' else ''}[bold cyan]2.[/bold cyan] Device List\n"
        menu += f"{'[reverse]' if self.state == 'LOGS' else ''}[bold blue]3.[/bold blue] Audit Logs\n\n"
        menu += "[bold red]Q.[/bold red] Quit"
        return Panel(menu, title="[bold]Menu[/bold]", border_style="blue")

    def make_main_view(self):
        if self.state == "MENU":
            warning = ""
            if self.last_discovery_summary and self.last_discovery_summary.get("scan_completion_state") == "budget_exceeded":
                duration = self.last_discovery_summary.get("run_duration_seconds", 0)
                limit = self.last_discovery_summary.get("script_timeout_seconds", 0)
                warning = (
                    f"[bold yellow]Last discovery exceeded its timeout budget.[/bold yellow]\n"
                    f"[dim]{duration:.1f}s ran against a {limit}s limit.[/dim]\n\n"
                )
            return Panel(
                f"\n\n{warning}[dim]Select an option to begin. Your environment will be mapped in real-time.[/dim]",
                title="Dashboard", border_style="dim"
            )
        elif self.state == "SCANNING":
            return self.make_live_scan_view()
        elif self.state == "INVENTORY":
            from rich.table import Table
            table = Table(box=None, expand=True)
            table.add_column("IP Address", style="bold cyan")
            table.add_column("MAC")
            table.add_column("Vendor", style="dim")
            table.add_column("System / OS", style="green")
            
            # windowed slice of the device list
            visible_devices = self.devices[self.scroll_index : self.scroll_index + 20]
            for dev in visible_devices:
                if isinstance(dev, dict):
                    ip_val = dev.get('ip', '?.?.?.?')
                    mac_val = dev.get('mac', 'N/A')
                    vendor_val = dev.get('vendor', 'Unknown')
                    system_val = f"{dev.get('type', 'Device')} ({dev.get('os', 'Unknown')})"
                else:
                    ip_val = dev[0] if len(dev) > 0 else '?.?.?.?'
                    mac_val = dev[1] if len(dev) > 1 else 'N/A'
                    os_val = dev[3] if len(dev) > 3 else 'Unknown'
                    vendor_val = dev[4] if len(dev) > 4 else 'Unknown'
                    system_val = f"Device ({os_val})"

                table.add_row(
                    ip_val,
                    mac_val,
                    vendor_val,
                    system_val
                )
            return Panel(table, title=f"[bold cyan]Inventory ({self.scroll_index}-{self.scroll_index + len(visible_devices)} of {len(self.devices)})[/bold cyan]", border_style="cyan")

        elif self.state == "LOGS":
            from rich.table import Table
            table = Table(box=None, expand=True)
            table.add_column("Level", style="dim", width=10)
            table.add_column("Message")
            
            for l in self.log_buffer:
                level = "info"
                msg = l
                if "]" in l:
                    level = l.split("]", 1)[0].replace("[", "").strip().lower()
                    msg = l.split("]", 1)[1].strip()
                
                table.add_row(f"[{level}]", msg)
            return Panel(table, title="audit logs", border_style="blue")
        
        return Panel("View Not Implemented", title="Error")

    def __rich__(self):
        l = Layout()
        l.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=1)
        )
        l["body"].split_row(
            Layout(name="sidebar", size=25),
            Layout(name="main", ratio=1)
        )
        
        l["header"].update(self.make_header())
        l["sidebar"].update(self.make_sidebar())
        l["main"].update(self.make_main_view())
        
        hints = "1-3: Select View | Q: Quit"
        if self.state == "INVENTORY":
            hints = "[W/S] Scroll | Esc: Back | Q: Quit"
        elif self.state == "SCANNING":
            hints = "[W/S] Select | N: Sort | F: Filter | C: Copy IP | M: Copy MAC | I: Inventory | Esc: Back | Q: Quit"
        elif self.state == "LOGS":
            hints = "Esc: Back | Q: Quit"
            
        l["footer"].update(f"[dim] {hints} [/dim]")
        return l

    def render(self):
        return self.__rich__()

if __name__ == "__main__":
    app = DashboardApp()
    app.console.print(app.render())
