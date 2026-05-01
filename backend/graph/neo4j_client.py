"""
Neo4j Client - Graph database connector for attack path analysis
Supports both Neo4j and in-memory graph for lightweight deployments
"""

import os
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from collections import defaultdict, deque
import json

# Try to import neo4j, fall back to in-memory if not available
try:
    from neo4j import GraphDatabase as Neo4jDriver, Result
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    logging.warning("Neo4j not installed. Using in-memory graph storage.")

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Neo4j graph database client with fallback to in-memory storage"""
    
    def __init__(self, uri: str = None, user: str = None, password: str = None):
        self.uri = uri or os.environ.get('NEO4J_URI', 'bolt://localhost:7687')
        self.user = user or os.environ.get('NEO4J_USER', 'neo4j')
        self.password = password or os.environ.get('NEO4J_PASSWORD', 'password')
        self.driver = None
        self.use_neo4j = False
        self._init_graph()
    
    def _init_graph(self):
        """Initialize graph connection or fallback to in-memory"""
        if NEO4J_AVAILABLE:
            try:
                self.driver = Neo4jDriver(self.uri, auth=(self.user, self.password))
                self.driver.verify_connectivity()
                self.use_neo4j = True
                logger.info(f"Connected to Neo4j at {self.uri}")
            except Exception as e:
                logger.warning(f"Failed to connect to Neo4j: {e}. Using in-memory graph.")
                self.use_neo4j = False
                self._init_memory_graph()
        else:
            self.use_neo4j = False
            self._init_memory_graph()
    
    def _init_memory_graph(self):
        """Initialize in-memory graph storage"""
        self.nodes = {}
        self.relationships = defaultdict(list)
        self.reverse_relationships = defaultdict(list)
        self.node_counter = 0
        logger.info("Initialized in-memory graph storage")
    
    def add_node(self, node_type: str, properties: Dict, node_id: str = None) -> str:
        """Add a node to the graph"""
        if self.use_neo4j:
            return self._add_node_neo4j(node_type, properties, node_id)
        else:
            return self._add_node_memory(node_type, properties, node_id)
    
    def _add_node_neo4j(self, node_type: str, properties: Dict, node_id: str = None) -> str:
        """Add node using Neo4j"""
        with self.driver.session() as session:
            if not node_id:
                node_id = f"{node_type}_{datetime.now().timestamp()}"
            
            query = """
            CREATE (n:Node {id: $id, type: $type, properties: $props, created_at: $timestamp})
            RETURN n
            """
            result = session.run(query, id=node_id, type=node_type, 
                               props=json.dumps(properties), 
                               timestamp=datetime.now().isoformat())
            return node_id
    
    def _add_node_memory(self, node_type: str, properties: Dict, node_id: str = None) -> str:
        """Add node to in-memory graph"""
        if not node_id:
            node_id = f"{node_type}_{self.node_counter}"
            self.node_counter += 1
        
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "properties": properties,
            "created_at": datetime.now().isoformat()
        }
        return node_id
    
    def add_relationship(self, from_node: str, to_node: str, rel_type: str, properties: Dict = None):
        """Add a relationship between nodes"""
        if self.use_neo4j:
            return self._add_relationship_neo4j(from_node, to_node, rel_type, properties)
        else:
            return self._add_relationship_memory(from_node, to_node, rel_type, properties)
    
    def _add_relationship_neo4j(self, from_node: str, to_node: str, rel_type: str, properties: Dict = None):
        """Add relationship using Neo4j"""
        with self.driver.session() as session:
            query = """
            MATCH (a {id: $from_id})
            MATCH (b {id: $to_id})
            CREATE (a)-[r:RELATIONSHIP {type: $rel_type, properties: $props, created_at: $timestamp}]->(b)
            RETURN r
            """
            session.run(query, from_id=from_node, to_id=to_node, 
                       rel_type=rel_type, props=json.dumps(properties or {}),
                       timestamp=datetime.now().isoformat())
    
    def _add_relationship_memory(self, from_node: str, to_node: str, rel_type: str, properties: Dict = None):
        """Add relationship to in-memory graph"""
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
    
    def find_paths(self, start_node: str, end_node_type: str = "root_access", max_depth: int = 10) -> List[List[Dict]]:
        """Find all attack paths from start to goal"""
        if self.use_neo4j:
            return self._find_paths_neo4j(start_node, end_node_type, max_depth)
        else:
            return self._find_paths_memory(start_node, end_node_type, max_depth)
    
    def _find_paths_neo4j(self, start_node: str, end_node_type: str, max_depth: int) -> List[List[Dict]]:
        """Find paths using Neo4j"""
        with self.driver.session() as session:
            query = """
            MATCH path = (start {id: $start_id})-[:RELATIONSHIP*1..%d]->(end)
            WHERE end.type = $end_type
            RETURN path
            """ % max_depth
            result = session.run(query, start_id=start_node, end_type=end_node_type)
            
            paths = []
            for record in result:
                path = []
                for node in record['path'].nodes:
                    path.append({
                        "id": node['id'],
                        "type": node['type'],
                        "properties": json.loads(node['properties']) if node['properties'] else {}
                    })
                paths.append(path)
            return paths
    
    def _find_paths_memory(self, start_node: str, end_node_type: str, max_depth: int) -> List[List[Dict]]:
        """Find paths using BFS on in-memory graph"""
        paths = []
        queue = deque([([start_node], {start_node})])
        
        while queue:
            path, visited = queue.popleft()
            current = path[-1]
            
            # Check depth limit
            if len(path) > max_depth:
                continue
            
            # Check if we reached goal
            if current in self.nodes and self.nodes[current]["type"] == end_node_type:
                full_path = []
                for node_id in path:
                    if node_id in self.nodes:
                        full_path.append({
                            "node_id": node_id,
                            "type": self.nodes[node_id]["type"],
                            "properties": self.nodes[node_id]["properties"]
                        })
                paths.append(full_path)
                continue
            
            # Explore neighbors
            for rel in self.relationships.get(current, []):
                if rel["to"] not in visited:
                    new_path = path + [rel["to"]]
                    new_visited = visited | {rel["to"]}
                    queue.append((new_path, new_visited))
        
        # Sort by path length
        paths.sort(key=len)
        return paths
    
    def get_node(self, node_id: str) -> Optional[Dict]:
        """Get node by ID"""
        if self.use_neo4j:
            with self.driver.session() as session:
                result = session.run("MATCH (n {id: $id}) RETURN n", id=node_id)
                record = result.single()
                if record:
                    node = record['n']
                    return {
                        "id": node['id'],
                        "type": node['type'],
                        "properties": json.loads(node['properties']) if node['properties'] else {}
                    }
                return None
        else:
            return self.nodes.get(node_id)
    
    def get_relationships(self, node_id: str, direction: str = "both") -> List[Dict]:
        """Get all relationships for a node"""
        if self.use_neo4j:
            return self._get_relationships_neo4j(node_id, direction)
        else:
            return self._get_relationships_memory(node_id, direction)
    
    def _get_relationships_neo4j(self, node_id: str, direction: str) -> List[Dict]:
        """Get relationships using Neo4j"""
        with self.driver.session() as session:
            if direction == "out":
                query = "MATCH (n {id: $id})-[r:RELATIONSHIP]->(m) RETURN r, m.id as target"
            elif direction == "in":
                query = "MATCH (m)-[r:RELATIONSHIP]->(n {id: $id}) RETURN r, m.id as source"
            else:
                query = "MATCH (n {id: $id})-[r:RELATIONSHIP]-(m) RETURN r, m.id as connected"
            
            result = session.run(query, id=node_id)
            relationships = []
            for record in result:
                rel = record['r']
                relationships.append({
                    "type": rel['type'],
                    "properties": json.loads(rel['properties']) if rel['properties'] else {},
                    "target": record.get('target'),
                    "source": record.get('source'),
                    "timestamp": rel['created_at']
                })
            return relationships
    
    def _get_relationships_memory(self, node_id: str, direction: str) -> List[Dict]:
        """Get relationships from in-memory graph"""
        relationships = []
        
        if direction in ["out", "both"]:
            relationships.extend(self.relationships.get(node_id, []))
        
        if direction in ["in", "both"]:
            relationships.extend(self.reverse_relationships.get(node_id, []))
        
        return relationships
    
    def delete_node(self, node_id: str) -> bool