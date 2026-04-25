from rich.layout import Layout
from rich.panel import Panel
from rich.header import Header
from rich.footer import Footer
from rich.console import Console
from datetime import datetime

class DashboardApp:
    def __init__(self):
        self.layout = Layout()
        self.console = Console()
        self.state = "MENU" # MENU, SCANNING, LOGS, INVENTORY
        self._init_layout()

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
        return Panel(
            f" [bold cyan]NetDocIT[/bold cyan] | [dim]Network Discovery & Inventory Engine[/dim] ",
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
            from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
            progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), transient=True)
            progress.add_task("Scanning Subnets...", total=100)
            return Panel(progress, title="[bold green]Live Discovery[/bold green]", border_style="green")
        
        return Panel("View Not Implemented", title="Error")

    def render(self):
        self.layout["header"].update(self.make_header())
        self.layout["sidebar"].update(self.make_sidebar())
        self.layout["main"].update(self.make_main_view())
        self.layout["footer"].update("[dim] Space: Refresh | Q: Quit | Esc: Back [/dim]")
        return self.layout

if __name__ == "__main__":
    # simple test to see the skeleton
    app = DashboardApp()
    app.console.print(app.render())
