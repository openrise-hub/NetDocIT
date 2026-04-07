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

    def save(self, filename="REPORT.md"):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(self.content))

if __name__ == "__main__":
    gen = MarkdownGenerator()
    gen.add_summary_section(2, {"windows": 2, "appliances": 2})
    gen.save("REPORT.md")
