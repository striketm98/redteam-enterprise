"""
Lab Orchestrator - Coordinate multi-container lab scenarios
"""

import time
import logging
from typing import Dict, List, Any
from datetime import datetime
from .deployer import LabDeployer
from .docker_manager import DockerManager

logger = logging.getLogger(__name__)


class LabOrchestrator:
    """Orchestrate complex multi-container lab scenarios"""
    
    def __init__(self):
        self.deployer = LabDeployer()
        self.docker_manager = DockerManager()
        self.active_scenarios = {}
    
    def deploy_scenario(self, scenario_name: str, scenario_config: Dict) -> Dict:
        """Deploy a complete lab scenario"""
        scenario_id = f"{scenario_name}_{int(time.time())}"
        
        result = {
            "scenario_id": scenario_id,
            "name": scenario_name,
            "status": "deploying",
            "deployed_services": [],
            "started_at": datetime.now().isoformat()
        }
        
        try:
            # Deploy each service in the scenario
            for service in scenario_config.get("services", []):
                lab_result = self.deployer.deploy_lab(
                    service["name"],
                    service.get("config", {})
                )
                result["deployed_services"].append(lab_result)
                time.sleep(2)  # Stagger deployments
            
            # Establish connections between services if specified
            if scenario_config.get("connections"):
                self._setup_connections(result["deployed_services"], scenario_config["connections"])
            
            result["status"] = "running"
            result["completed_at"] = datetime.now().isoformat()
            
            self.active_scenarios[scenario_id] = result
            
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
        
        return result
    
    def _setup_connections(self, services: List[Dict], connections: List[Dict]):
        """Setup network connections between services"""
        for conn in connections:
            source = conn.get("source")
            target = conn.get("target")
            network = conn.get("network", "redteam-lab-net")
            
            # Connect containers to the same network
            for service in services:
                if service.get("name") == source or service.get("lab_id") == source:
                    self._connect_to_network(service["lab_id"], network)
                if service.get("name") == target or service.get("lab_id") == target:
                    self._connect_to_network(service["lab_id"], network)
    
    def _connect_to_network(self, container_id: str, network: str):
        """Connect a container to a network"""
        try:
            cmd = f"docker network connect {network} {container_id}"
            import subprocess
            subprocess.run(cmd.split(), capture_output=True)
        except:
            pass
    
    def get_scenario_status(self, scenario_id: str) -> Dict:
        """Get status of a deployed scenario"""
        if scenario_id not in self.active_scenarios:
            return {"error": "Scenario not found"}
        
        scenario = self.active_scenarios[scenario_id]
        
        # Update status of each service
        for service in scenario["deployed_services"]:
            updated = self.deployer.get_lab_status(service["lab_id"])
            if updated:
                service.update(updated)
        
        return scenario
    
    def stop_scenario(self, scenario_id: str) -> bool:
        """Stop a deployed scenario"""
        if scenario_id not in self.active_scenarios:
            return False
        
        scenario = self.active_scenarios[scenario_id]
        
        # Stop all services in the scenario
        for service in scenario["deployed_services"]:
            self.deployer.stop_lab(service["lab_id"])
        
        scenario["status"] = "stopped"
        scenario["stopped_at"] = datetime.now().isoformat()
        
        return True
    
    def list_scenarios(self) -> List[Dict]:
        """List all active scenarios"""
        return list(self.active_scenarios.values())
    
    def get_scenario_network_map(self, scenario_id: str) -> Dict:
        """Get network topology map for a scenario"""
        if scenario_id not in self.active_scenarios:
            return {"error": "Scenario not found"}
        
        scenario = self.active_scenarios[scenario_id]
        network_map = {
            "scenario": scenario["name"],
            "nodes": [],
            "connections": []
        }
        
        for service in scenario["deployed_services"]:
            network_map["nodes"].append({
                "id": service["lab_id"],
                "name": service["name"],
                "ip": service.get("ip"),
                "ports": service.get("ports", {})
            })
        
        return network_map
    
    def health_check(self, scenario_id: str) -> Dict:
        """Perform health check on all services in a scenario"""
        if scenario_id not in self.active_scenarios:
            return {"error": "Scenario not found"}
        
        results = {"healthy": [], "unhealthy": []}
        scenario = self.active_scenarios[scenario_id]
        
        for service in scenario["deployed_services"]:
            status = self.deployer.get_lab_status(service["lab_id"])
            if status and status.get("status") == "running":
                results["healthy"].append(service["lab_id"])
            else:
                results["unhealthy"].append(service["lab_id"])
        
        results["total"] = len(scenario["deployed_services"])
        results["healthy_count"] = len(results["healthy"])
        
        return results


# Singleton instance
lab_orchestrator = LabOrchestrator()