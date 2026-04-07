import networkx as nx

class TopologyManager:
    def __init__(self):
        self.graph = nx.Graph()
        
    def build_from_discovery(self, discovery_summary):
        # local scanning host (Root node)
        self.graph.add_node("Host", type="server", label="NetDocIT Host")
        
        # find active host interfaces
        for iface in discovery_summary.get('interfaces', []):
            iface_id = f"iface:{iface['name']}"
            self.graph.add_node(iface_id, type="interface", label=f"{iface['name']} ({iface['ipv4']})")
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
                    
                    self.graph.add_node(subnet_id, type="subnet", label=f"{tag} ({route['network']})")
                    self.graph.add_edge(iface_id, subnet_id)

    def get_stats(self):
        return f"Topology built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges."

if __name__ == "__main__":
    tm = TopologyManager()
    temp = {
        "interfaces": [{"name": "eth0", "ipv4": "192.168.1.10"}],
        "routes": [{"interface": "eth0", "network": "192.168.1.0"}],
        "subnets": [{"cidr": "192.168.1.0/24", "tag": "Home Network"}]
    }
    tm.build_from_discovery(temp)
    print(tm.get_stats())
