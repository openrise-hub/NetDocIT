import ipaddress

try:
    import networkx as nx
except ModuleNotFoundError:
    class _NodeView:
        def __init__(self, graph):
            self._graph = graph

        def __iter__(self):
            return iter(self._graph._nodes)

        def __contains__(self, item):
            return item in self._graph._nodes

        def __getitem__(self, item):
            return self._graph._nodes[item]

        def __call__(self, data=False):
            if data:
                return list(self._graph._nodes.items())
            return list(self._graph._nodes.keys())

    class _SimpleGraph:
        def __init__(self):
            self._nodes = {}
            self._edges = {}

        @property
        def nodes(self):
            return _NodeView(self)

        def add_node(self, node, **attrs):
            self._nodes.setdefault(node, {}).update(attrs)

        def add_edge(self, left, right, **attrs):
            edge_key = frozenset((left, right))
            self._edges[edge_key] = dict(attrs)

        def get_edge_data(self, left, right):
            return self._edges.get(frozenset((left, right)))

        def number_of_nodes(self):
            return len(self._nodes)

        def number_of_edges(self):
            return len(self._edges)

        def neighbors(self, node):
            for edge_key in self._edges:
                if node in edge_key:
                    for neighbor in edge_key:
                        if neighbor != node:
                            yield neighbor

    class _FallbackNetworkX:
        Graph = _SimpleGraph

    nx = _FallbackNetworkX()

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

        for subnet in discovery_summary.get('subnets', []):
            if not isinstance(subnet, dict):
                continue
            cidr = subnet.get('cidr')
            if not cidr:
                continue
            subnet_id = f"subnet:{cidr}"
            if subnet_id not in self.graph.nodes:
                self.graph.add_node(
                    subnet_id,
                    type="subnet",
                    label=f"{subnet.get('tag', 'Unlabeled')}\n{cidr}",
                    shape="database",
                    color="#2ecc71",
                    size=25,
                    cidr=cidr,
                )

        subnet_nodes = {}
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'subnet' and data.get('cidr'):
                subnet_nodes[data['cidr']] = node

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

        for placement in discovery_summary.get('asset_placements', []):
            if not isinstance(placement, dict):
                continue

            asset_id = f"asset:{placement.get('canonical_asset_id')}"
            label = placement.get('label') or placement.get('canonical_key') or asset_id
            state = placement.get('state', 'certain')
            self.graph.add_node(
                asset_id,
                type="asset",
                label=label,
                shape="ellipse",
                color="#8e44ad" if state == 'certain' else "#d35400",
                placement_state=state,
                title=f"Asset: {label}<br>State: {state}",
            )

            primary = placement.get('primary')
            if isinstance(primary, dict):
                primary_node = subnet_nodes.get(primary.get('subnet_cidr'))
                if primary_node:
                    self.graph.add_edge(
                        primary_node,
                        asset_id,
                        placement_kind="primary",
                        dashes=False,
                        style="solid",
                        label=primary.get('rationale', ''),
                    )

            for alternate in placement.get('alternates', []):
                if not isinstance(alternate, dict):
                    continue
                alternate_node = subnet_nodes.get(alternate.get('subnet_cidr'))
                if alternate_node:
                    self.graph.add_edge(
                        alternate_node,
                        asset_id,
                        placement_kind="alternate",
                        dashes=True,
                        style="dashed",
                        label=alternate.get('rationale', ''),
                    )

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
        from pyvis.network import Network  # pyright: ignore[reportMissingImports]
        
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
