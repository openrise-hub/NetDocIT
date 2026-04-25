from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console
from datetime import datetime

class DashboardApp:
    def __init__(self):
        self.layout = Layout()
        self.console = Console()
        self.state = "MENU"
        self.log_buffer = [] 
        self.devices = [] # current session hosts
        self.scroll_index = 0 # position for table windowing
        self._init_layout()

    def add_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_buffer.append(f"[dim]{timestamp}[/dim] {message}")
        if len(self.log_buffer) > 100:
            self.log_buffer.pop(0)

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
            return Panel(
                "\n\n[dim]Select an option to begin. Your environment will be mapped in real-time.[/dim]",
                title="Dashboard", border_style="dim"
            )
        elif self.state == "SCANNING":
            from rich.progress import Progress, SpinnerColumn, TextColumn
            from rich.console import Group
            progress = Progress(SpinnerColumn(), TextColumn("[bold green]{task.description}"))
            progress.add_task("Active Discovery Pipeline Running...")
            log_display = "\n".join(self.log_buffer[-10:])
            return Panel(
                Group(progress, Panel(log_display, title="Recent Events", border_style="dim")),
                title="[bold green]Scan Center[/bold green]", border_style="green"
            )
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
                table.add_row(
                    dev.get('ip', '?.?.?.?'),
                    dev.get('mac', 'N/A'),
                    dev.get('vendor', 'Unknown'),
                    f"{dev.get('type', 'Device')} ({dev.get('os', 'Unknown')})"
                )
            return Panel(table, title=f"[bold cyan]Inventory ({self.scroll_index}-{self.scroll_index + len(visible_devices)} of {len(self.devices)})[/bold cyan]", border_style="cyan")

        elif self.state == "LOGS":
            from rich.table import Table
            table = Table(box=None, expand=True)
            table.add_column("Timestamp", style="dim", width=12)
            table.add_column("Message")
            for entry in self.log_buffer[-20:]:
                parts = entry.split(" ", 1)
                table.add_row(parts[0], parts[1])
            return Panel(table, title="[bold blue]Session Audit Logs[/bold blue]", border_style="blue")
        
        return Panel("View Not Implemented", title="Error")

    def render(self):
        self.layout["header"].update(self.make_header())
        self.layout["sidebar"].update(self.make_sidebar())
        self.layout["main"].update(self.make_main_view())
        
        # contextual footer hints
        hints = "[dim] 1-3: Select View | Q: Quit [/dim]"
        if self.state == "INVENTORY":
            hints = "[dim] [W/S] Scroll | Esc: Back | Q: Quit [/dim]"
        elif self.state == "LOGS":
            hints = "[dim] Esc: Back | Q: Quit [/dim]"
            
        self.layout["footer"].update(hints)
        return self.layout

if __name__ == "__main__":
    app = DashboardApp()
    app.console.print(app.render())
