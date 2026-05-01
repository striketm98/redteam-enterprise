import logging
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Neo4jClient:
    """Lightweight graph database implementation for attack path analysis"""
    
    def __init__(self):
        self.nodes = {}
        self.relationships = defaultdict(list)
        self.reverse_relationships = defaultdict(list)
        self.node_counter = 0
    
    def add_node(self, node_type: str, properties: Dict) -> str:
        """Add a node to the graph"""
        node_id = f"{node_type}_{self.node_counter}"
        self.nodes[node_id] = {
            "type": node_type,
            "properties": properties,
            "created": datetime.now().isoformat()
        }
        self.node_counter += 1
        return node_id
    
    def add_relationship(self, from_node: str, to_node: str, rel_type: str, properties: Dict = None):
        """Add a relationship between nodes"""
        if from_node not in self.nodes or to_node not in self.nodes:
            logger.error(f"Invalid nodes: {from_node} -> {to_node}")
            return
        
        relationship = {
            "from": from_node,
            "to": to_node,
            "type": rel_type,
            "properties": properties or {},
            "timestamp": datetime.now().isoformat()
        }
        
        self.relationships[from_node].append(relationship)
        self.reverse_relationships[to_node].append(relationship)
        logger.info(f"Added relationship: {from_node} -[{rel_type}]-> {to_node}")
    
    def find_attack_paths(self, start_node: str, end_node_type: str = "root_access") -> List[List[Dict]]:
        """Find all attack paths from start to goal"""
        paths = []
        
        # BFS to find paths
        queue = deque([([start_node], {start_node})])
        
        while queue:
            path, visited = queue.popleft()
            current = path[-1]
            
            # Check if we reached goal
            if self.nodes[current]["type"] == end_node_type:
                # Convert node IDs to full path details
                full_path = []
                for node_id in path:
                    full_path.append({
                        "node_id": node_id,
                        "type": self.nodes[node_id]["type"],
                        "properties": self.nodes[node_id]["properties"]
                    })
                paths.append(full_path)
                continue
            
            # Explore neighbors
            for rel in self.relationships[current]:
                if rel["to"] not in visited:
                    new_path = path + [rel["to"]]
                    new_visited = visited | {rel["to"]}
                    queue.append((new_path, new_visited))
        
        # Sort paths by length (shortest first)
        paths.sort(key=len)
        return paths
    
    def get_node_relationships(self, node_id: str, direction: str = "both") -> List[Dict]:
        """Get all relationships for a node"""
        relationships = []
        
        if direction in ["out", "both"]:
            relationships.extend(self.relationships.get(node_id, []))
        
        if direction in ["in", "both"]:
            relationships.extend(self.reverse_relationships.get(node_id, []))
        
        return relationships
    
    def build_attack_tree(self, target_node: str) -> Dict:
        """Build attack tree showing how to reach target"""
        attack_tree = {
            "target": target_node,
            "paths": [],
            "critical_nodes": set(),
            "redundant_paths": []
        }
        
        # Find all paths to target
        for node_id in self.nodes:
            if node_id != target_node:
                paths = self.find_attack_paths(node_id, self.nodes[target_node]["type"])
                if paths:
                    for path in paths:
                        attack_tree["paths"].append({
                            "source": node_id,
                            "path": path,
                            "length": len(path)
                        })
                        
                        # Identify critical nodes (appear in many paths)
                        for step in path:
                            attack_tree["critical_nodes"].add(step["node_id"])
        
        attack_tree["critical_nodes"] = list(attack_tree["critical_nodes"])
        
        return attack_tree
    
    def export_to_json(self) -> Dict:
        """Export entire graph to JSON format"""
        return {
            "nodes": self.nodes,
            "relationships": dict(self.relationships),
            "stats": {
                "total_nodes": len(self.nodes),
                "total_relationships": sum(len(v) for v in self.relationships.values()),
                "node_types": self._get_node_type_stats()
            }
        }
    
    def _get_node_type_stats(self) -> Dict:
        """Get statistics about node types"""
        stats = defaultdict(int)
        for node in self.nodes.values():
            stats[node["type"]] += 1
        return dict(stats)
    
    def clear(self):
        """Clear all graph data"""
        self.nodes = {}
        self.relationships = defaultdict(list)
        self.reverse_relationships = defaultdict(list)
        self.node_counter = 0
        logger.info("Graph cleared")


class GraphAnalyzer:
    """Analyzer for attack path optimization"""
    
    def __init__(self, graph_client: Neo4jClient):
        self.graph = graph_client
    
    def find_optimal_path(self, start: str, goal_type: str) -> Optional[List[str]]:
        """Find most efficient attack path using weighted scoring"""
        paths = self.graph.find_attack_paths(start, goal_type)
        
        if not paths:
            return None
        
        # Score paths based on number of steps and node types
        scored_paths = []
        for path in paths:
            score = 0
            
            # Shorter paths are better
            score -= len(path) * 10
            
            # Prefer paths with known exploits
            for node in path:
                if "exploit" in node["properties"].get("risk", "").lower():
                    score += 20
                if node["type"] == "credential":
                    score += 15
            
            scored_paths.append((score, path))
        
        # Return best path
        scored_paths.sort(reverse=True)
        return [node["node_id"] for node in scored_paths[0][1]]
    
    def identify_bottlenecks(self) -> List[Dict]:
        """Identify bottlenecks in the attack graph"""
        bottlenecks = []
        node_usage = defaultdict(int)
        
        # Count how many paths go through each node
        for rel_list in self.graph.relationships.values():
            for rel in rel_list:
                node_usage[rel["to"]] += 1
        
        # Nodes that appear frequently are bottlenecks
        for node_id, usage in node_usage.items():
            if usage > 5:  # Threshold
                bottlenecks.append({
                    "node": node_id,
                    "type": self.graph.nodes[node_id]["type"],
                    "usage_count": usage,
                    "impact": "High" if usage > 10 else "Medium"
                })
        
        return sorted(bottlenecks, key=lambda x: x["usage_count"], reverse=True)