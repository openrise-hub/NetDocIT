import networkx as nx
import ipaddress

class TopologyManager:
    def __init__(self):
        self.graph = nx.Graph()
        
    def build_from_discovery(self, discovery_summary):
        # local scanning host (Root node)
        self.graph.add_node(
            "Host", 
            type="server", 
            label="NetDocIT Host",
            shape="star",
            color="#e74c3c",
            size=30
        )
        
        # find active host interfaces
        for iface in discovery_summary.get('interfaces', []):
            iface_id = f"iface:{iface['name']}"
            
            # format ip
            str_ip = iface['ipv4'] if iface['ipv4'] else "No IP"
            self.graph.add_node(
                iface_id, 
                type="interface", 
                label=f"{iface['name']}\n{str_ip}",
                shape="dot",
                color="#3498db",
                size=21
            )
            self.graph.add_edge("Host", iface_id)
            
            # map subnets to their interfaces
            for route in discovery_summary.get('routes', []):
                if route['interface'] == iface['name'] and route['network'] != "0.0.0.0":
                    subnet_id = f"subnet:{route['network']}"
                    
                    tag = "Unlabeled"
                    cidr = ""
                    for sn in discovery_summary.get('subnets', []):
                        if sn['cidr'].split('/')[0] == route['network']:
                            tag = sn['tag']
                            cidr = sn['cidr']
                            break
                    
                    self.graph.add_node(
                        subnet_id, 
                        type="subnet", 
                        label=f"{tag}\n{route['network']}",
                        shape="database",
                        color="#2ecc71",
                        size=25,
                        cidr=cidr
                    )
                    self.graph.add_edge(iface_id, subnet_id)

        scan_data = discovery_summary.get('scan_data', [])
        all_devices = {d['ip']: d for d in scan_data}
        
        for d in discovery_summary.get('host_data', []):
            if d['ip'] in all_devices:
                all_devices[d['ip']].update(d)
        for d in discovery_summary.get('snmp_data', []):
            if d['ip'] in all_devices:
                all_devices[d['ip']].update(d)

        for ip, dev in all_devices.items():
            parent_subnet = None
            try:
                ip_obj = ipaddress.ip_address(ip)
                for node, data in self.graph.nodes(data=True):
                    if data.get('type') == 'subnet' and data.get('cidr'):
                        net_obj = ipaddress.ip_network(data['cidr'])
                        if ip_obj in net_obj:
                            parent_subnet = node
                            break
            except Exception:
                continue

            if parent_subnet:
                dev_id = f"dev:{ip}"
                is_windows = "Windows" in dev.get('os', '')
                shape = "box" if is_windows else "triangle"
                color = "#9b59b6" if is_windows else "#f1c40f"
                
                label = dev.get('hostname', ip)
                if label == "Active-Host": label = ip
                
                title = f"IP: {ip}<br>MAC: {dev.get('mac', 'Unknown')}<br>Vendor: {dev.get('vendor', 'Unknown')}<br>OS: {dev.get('os', 'Unknown')}"
                
                self.graph.add_node(
                    dev_id,
                    type="device",
                    label=label,
                    shape=shape,
                    color=color,
                    title=title,
                    size=15
                )
                self.graph.add_edge(parent_subnet, dev_id)

    def get_stats(self):
        return f"Topology built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges."

    def display_tui(self):
        from rich import print as rprint
        from rich.tree import Tree
        
        # terminal tree root
        tree = Tree("[bold cyan]Network Discovery Tree[/bold cyan]")
        
        # traverse host interfaces
        for iface in self.graph.neighbors("Host"):
            label = self.graph.nodes[iface].get('label', iface)
            branch = tree.add(f"[bold green]Interface:[/bold green] {label}")
            
            # add associated subnets
            for subnet in self.graph.neighbors(iface):
                if subnet == "Host": continue
                sub_label = self.graph.nodes[subnet].get('label', subnet)
                branch.add(f"[bold yellow]Subnet:[/bold yellow] {sub_label}")
                
        rprint(tree)

    def save_html_map(self, output_path="index.html"):
        from pyvis.network import Network
        
        # translate networkx graph to interactive html
        net = Network(notebook=False, directed=False, heading="NetDocIT Topology", height="800px", width="100%")
        
        # configure physics to prevent overlap
        net.repulsion(
            node_distance=150,
            central_gravity=0.33,
            spring_length=210,
            spring_strength=0.06,
            damping=0.09
        )
        
        net.from_nx(self.graph)
        net.save_graph(output_path)

if __name__ == "__main__":
    tm = TopologyManager()
    temp = {
        "interfaces": [{"name": "eth0", "ipv4": "192.168.1.10"}],
        "routes": [{"interface": "eth0", "network": "192.168.1.0"}],
        "subnets": [{"cidr": "192.168.1.0/24", "tag": "Home Network"}]
    }
    tm.build_from_discovery(temp)
    print(tm.get_stats())
    tm.display_tui()
    tm.save_html_map("test_map.html")
