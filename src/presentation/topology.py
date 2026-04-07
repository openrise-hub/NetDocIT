import networkx as nx

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
                    for sn in discovery_summary.get('subnets', []):
                        if sn['cidr'].startswith(route['network']):
                            tag = sn['tag']
                            break
                    
                    self.graph.add_node(
                        subnet_id, 
                        type="subnet", 
                        label=f"{tag}\n{route['network']}",
                        shape="database",
                        color="#2ecc71",
                        size=25
                    )
                    self.graph.add_edge(iface_id, subnet_id)

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
