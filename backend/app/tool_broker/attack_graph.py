import networkx as nx
import json
import uuid

class AttackGraphEngine:
    """
    World-Class Upgrade: The Attack Graph Engine
    Instead of isolated scans, AegisTwin now builds a mathematical, memory-persistent
    directed graph of the target infrastructure. When a vulnerability is found on one node,
    the graph calculates lateral movement paths (Kill Chains) to compromise connected nodes,
    simulating an APT (Advanced Persistent Threat) autonomously.
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_registry = {}
        
    def add_asset_node(self, asset_type: str, value: str, confidence: float = 1.0):
        """Register a new asset (e.g., Domain, IP, Open Port, API Endpoint)"""
        node_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, value))
        
        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                type=asset_type,
                value=value,
                confidence=confidence,
                vulnerabilities=[],
                compromised=False
            )
            self.node_registry[value] = node_id
        return node_id
        
    def add_vulnerability(self, target_value: str, cve: str, severity: float, requires_auth: bool):
        """Bind a discovered vulnerability to an asset node."""
        node_id = self.node_registry.get(target_value)
        if not node_id:
            return False
            
        vuln_data = {
            "cve": cve,
            "severity": severity,
            "requires_auth": requires_auth
        }
        self.graph.nodes[node_id]['vulnerabilities'].append(vuln_data)
        
        # If severity is critical and no auth required, mathematically flag as compromised
        if severity >= 9.0 and not requires_auth:
            self.graph.nodes[node_id]['compromised'] = True
            self._recalculate_lateral_paths()
            
        return True
        
    def create_relationship(self, source_value: str, target_value: str, relation_type: str):
        """Map dependencies (e.g., Subdomain -> points_to -> IP -> runs_service -> HTTP)"""
        src_id = self.node_registry.get(source_value)
        dst_id = self.node_registry.get(target_value)
        
        if src_id and dst_id:
            self.graph.add_edge(src_id, dst_id, type=relation_type, weight=1.0)
            return True
        return False
        
    def _recalculate_lateral_paths(self):
        """
        Advanced: When a node falls, find all downstream nodes that can be 
        pivoted into using shortest-path graph traversal.
        """
        compromised_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('compromised')]
        for comp_node in compromised_nodes:
            # Find all reachable targets from this beachhead
            reachable = nx.descendants(self.graph, comp_node)
            for target in reachable:
                # E.g. if we compromise a server, we implicitly trust the internal DB
                if self.graph.edges.get((comp_node, target), {}).get('type') == 'has_internal_access':
                    self.graph.nodes[target]['compromised'] = True

    def generate_kill_chain_report(self):
        """Export the graph as an actionable APT kill chain summary."""
        report = []
        for n, d in self.graph.nodes(data=True):
            if d.get('compromised'):
                report.append({
                    "asset": d['value'],
                    "type": d['type'],
                    "status": "COMPROMISED",
                    "attack_vectors": d['vulnerabilities']
                })
        return json.dumps(report, indent=2)

# Singleton instance
graph_engine = AttackGraphEngine()
