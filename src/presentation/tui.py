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
        self._init_layout()

    def _init_layout(self):
        # build the visual skeleton
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
        # navigation links
        menu = "[bold green]1.[/bold green] Start Discovery\n"
        menu += "[bold cyan]2.[/bold cyan] View Map\n"
        menu += "[bold yellow]3.[/bold yellow] Reports\n"
        menu += "[bold blue]4.[/bold blue] Audit Logs\n\n"
        menu += "[bold red]Q.[/bold red] Quit"
        return Panel(menu, title="[bold]Menu[/bold]", border_style="blue")

    def make_main_placeholder(self):
        # default view when no task is running
        return Panel(
            "\n\n[dim]Select an option from the sidebar to begin mapping your environment.[/dim]",
            title="Dashboard",
            border_style="dim"
        )

    def render(self):
        # update the content of each pane
        self.layout["header"].update(self.make_header())
        self.layout["sidebar"].update(self.make_sidebar())
        self.layout["main"].update(self.make_main_placeholder())
        self.layout["footer"].update("[dim] Space: Refresh | Q: Quit | Esc: Back [/dim]")
        
        return self.layout

if __name__ == "__main__":
    # simple test to see the skeleton
    app = DashboardApp()
    app.console.print(app.render())
