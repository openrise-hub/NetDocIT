import os
import json
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

    def add_drift_section(self, drift_report):
        if not drift_report:
            return
        self.add_header("Delta And Drift", 2)
        summary = drift_report.get("summary", {})
        self.content.append(f"- **Added:** {summary.get('added', 0)}")
        self.content.append(f"- **Removed:** {summary.get('removed', 0)}")
        self.content.append(f"- **Modified:** {summary.get('modified', 0)}")
        self.content.append("")

    def save(self, filename="REPORT.md"):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(self.content))

    def save_html(self, subnet_count, dev_stats, devices, filename="inventory.html", provenance=None, health_report=None, drift_report=None):
        from jinja2 import Environment, FileSystemLoader
        
        # setup jinja2 to load the template folder
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('inventory.html')
        
        # render the data into the dashboard
        self.provenance = provenance
        self.health_report = health_report
        self.drift_report = drift_report
        provenance_json = "{}"
        if provenance is not None:
            provenance_json = json.dumps(provenance, ensure_ascii=False, separators=(",", ":"))

        health_json = "{}"
        if health_report is not None:
            health_json = json.dumps(health_report, ensure_ascii=False, separators=(",", ":"))

        drift_json = "{}"
        if drift_report is not None:
            drift_json = json.dumps(drift_report, ensure_ascii=False, separators=(",", ":"))

        output = template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            subnet_count=subnet_count,
            windows_count=dev_stats['windows'],
            appliance_count=dev_stats['appliances'],
            devices=devices,
            provenance_json=provenance_json,
            health_json=health_json,
            drift_json=drift_json,
        )
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(output)

if __name__ == "__main__":
    gen = MarkdownGenerator()
    gen.add_summary_section(2, {"windows": 2, "appliances": 2})
    gen.save("REPORT.md")
