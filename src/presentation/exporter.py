import os
from datetime import datetime

class MarkdownGenerator:
    def __init__(self):
        self.content = []
        
    def add_header(self, title, level=1):
        # generate markdown headers
        self.content.append(f"{'#' * level} {title}\n")
        
    def add_summary_section(self, subnet_count, device_stats):
        self.add_header("Network Discovery Report", 1)
        self.content.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.content.append("## Summary")
        self.content.append(f"- **Subnets Tracked:** {subnet_count}")
        self.content.append(f"- **Windows Hosts:** {device_stats['windows']}")
        self.content.append(f"- **Network Appliances:** {device_stats['appliances']}\n")

    def add_device_table(self, devices):
        # generate the active device inventory table
        self.add_header("Active Device Inventory", 2)
        self.content.append("| IP Address | Hostname | Manufacturer | OS / Type | MAC Address |")
        self.content.append("|------------|----------|--------------|-----------|-------------|")
        
        for ip, mac, host, os_val, vendor in devices:
            self.content.append(f"| {ip} | {host} | {vendor} | {os_val} | {mac} |")
        self.content.append("")

    def save(self, filename="REPORT.md"):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(self.content))

    def save_html(self, subnet_count, dev_stats, devices, filename="inventory.html"):
        from jinja2 import Environment, FileSystemLoader
        
        # setup jinja2 to load the template folder
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('inventory.html')
        
        # render the data into the dashboard
        output = template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            subnet_count=subnet_count,
            windows_count=dev_stats['windows'],
            appliance_count=dev_stats['appliances'],
            devices=devices
        )
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(output)

if __name__ == "__main__":
    gen = MarkdownGenerator()
    gen.add_summary_section(2, {"windows": 2, "appliances": 2})
    gen.save("REPORT.md")
