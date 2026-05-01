"""
Lab Deployer - Deploy and manage vulnerable lab environments
"""

import subprocess
import time
import json
import logging
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
from .templates.vulnerable_apps import VULNERABLE_IMAGES
from .templates.network_topologies import NETWORK_TOPOLOGIES

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LabDeployer:
    """Deploy and manage vulnerable lab environments"""
    
    def __init__(self):
        self.active_labs = {}
        self.networks = {}
        
        # Available vulnerable images
        self.available_images = {
            # Web Vulnerabilities
            "dvwa": {
                "image": "vulnerables/web-dvwa",
                "ports": {"80": "80"},
                "description": "Damn Vulnerable Web Application - SQLi, XSS, CSRF, File Inclusion",
                "difficulty": "Beginner",
                "tags": ["web", "sql", "xss"]
            },
            "juice_shop": {
                "image": "bkimminich/juice-shop",
                "ports": {"3000": "3000"},
                "description": "OWASP Juice Shop - Modern web vulnerabilities",
                "difficulty": "Intermediate",
                "tags": ["web", "api", "jwt"]
            },
            "wordpress": {
                "image": "wordpress:latest",
                "ports": {"8080": "80"},
                "description": "Vulnerable WordPress installation",
                "difficulty": "Beginner",
                "tags": ["web", "cms"]
            },
            
            # Network Vulnerabilities
            "metasploitable2": {
                "image": "tleemcjr/metasploitable2",
                "ports": {"22": "22", "80": "80", "445": "445", "3306": "3306"},
                "description": "Metasploitable 2 - Multiple network vulnerabilities",
                "difficulty": "Intermediate",
                "tags": ["network", "smb", "ssh", "mysql"]
            },
            "metasploitable3": {
                "image": "rapid7/metasploitable3",
                "ports": {"22": "22", "80": "80", "3389": "3389", "5985": "5985"},
                "description": "Metasploitable 3 - Windows/Linux vulnerabilities",
                "difficulty": "Advanced",
                "tags": ["network", "windows", "linux"]
            },
            
            # SSH Vulnerabilities
            "ssh_weak": {
                "image": "vulnerables/ssh-weak",
                "ports": {"2222": "22"},
                "description": "SSH server with weak credentials",
                "difficulty": "Beginner",
                "tags": ["ssh", "bruteforce"]
            },
            
            # Database Vulnerabilities
            "mysql_vuln": {
                "image": "mysql:5.5",
                "ports": {"3306": "3306"},
                "description": "MySQL with default credentials",
                "difficulty": "Beginner",
                "tags": ["database", "mysql"]
            },
            
            # Active Directory
            "ad_light": {
                "image": "outflanknl/ad-light",
                "ports": {"389": "389", "636": "636", "445": "445"},
                "description": "Lightweight Active Directory environment",
                "difficulty": "Advanced",
                "tags": ["ad", "ldap", "smb"]
            },
            
            # Custom Vulnerable Apps
            "bodgeit": {
                "image": "psiinon/bodgeit",
                "ports": {"8080": "8080"},
                "description": "Bodgeit Store - J2EE vulnerable web app",
                "difficulty": "Intermediate",
                "tags": ["web", "java"]
            },
            "webgoat": {
                "image": "webgoat/goatandwolf",
                "ports": {"8080": "8080"},
                "description": "WebGoat - Web application security training",
                "difficulty": "Beginner",
                "tags": ["web", "training"]
            }
        }
    
    def deploy_lab(self, lab_name: str, config: Dict = None) -> Dict:
        """Deploy a lab environment"""
        if lab_name not in self.available_images:
            return {"error": f"Unknown lab: {lab_name}. Available: {list(self.available_images.keys())}"}
        
        lab_id = f"{lab_name}_{int(time.time())}"
        lab_config = self.available_images[lab_name]
        
        try:
            # Create network if not exists
            network_name = "redteam-lab-net"
            self._create_network(network_name)
            
            # Deploy container
            cmd = f"docker run -d --name {lab_id} --network {network_name}"
            
            # Add port mappings
            ports = config.get("ports", {}) if config else {}
            ports.update(lab_config.get("ports", {}))
            
            for host_port, container_port in ports.items():
                cmd += f" -p {host_port}:{container_port}"
            
            # Add environment variables
            env_vars = config.get("env", {}) if config else {}
            for key, value in env_vars.items():
                cmd += f" -e {key}={value}"
            
            cmd += f" {lab_config['image']}"
            
            container_id = self._run_docker_command(cmd)
            
            lab_info = {
                "lab_id": lab_id,
                "name": lab_name,
                "image": lab_config["image"],
                "description": lab_config["description"],
                "difficulty": lab_config["difficulty"],
                "tags": lab_config["tags"],
                "status": "deploying",
                "created": datetime.now().isoformat(),
                "config": config or {},
                "container_id": container_id.strip(),
                "ports": ports
            }
            
            # Wait for container to be ready
            time.sleep(5)
            lab_info["status"] = self._get_container_status(lab_id)
            lab_info["ip"] = self._get_container_ip(lab_id)
            
            self.active_labs[lab_id] = lab_info
            logger.info(f"Lab deployed: {lab_name} ({lab_id}) at {lab_info['ip']}")
            
            return lab_info
            
        except Exception as e:
            logger.error(f"Failed to deploy lab: {e}")
            return {"error": str(e)}
    
    def deploy_multi_target(self, targets: List[Dict]) -> List[Dict]:
        """Deploy multiple targets for lateral movement practice"""
        results = []
        
        for target_config in targets:
            lab_name = target_config.get("name")
            config = target_config.get("config", {})
            
            result = self.deploy_lab(lab_name, config)
            results.append(result)
            
            # Small delay between deployments
            time.sleep(2)
        
        logger.info(f"Deployed {len(results)} targets")
        return results
    
    def deploy_topology(self, topology_name: str) -> Dict:
        """Deploy a complete network topology"""
        if topology_name not in NETWORK_TOPOLOGIES:
            return {"error": f"Unknown topology: {topology_name}"}
        
        topology = NETWORK_TOPOLOGIES[topology_name]
        results = {
            "topology": topology_name,
            "description": topology["description"],
            "deployed_services": []
        }
        
        for service in topology["services"]:
            result = self.deploy_lab(service["name"], service.get("config", {}))
            results["deployed_services"].append(result)
            time.sleep(3)
        
        results["status"] = "deployed"
        results["deployed_at"] = datetime.now().isoformat()
        
        return results
    
    def stop_lab(self, lab_id: str) -> bool:
        """Stop and remove a lab"""
        try:
            self._run_docker_command(f"stop {lab_id}")
            self._run_docker_command(f"rm {lab_id}")
            
            if lab_id in self.active_labs:
                self.active_labs[lab_id]["status"] = "stopped"
                del self.active_labs[lab_id]
            
            logger.info(f"Lab stopped: {lab_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop lab: {e}")
            return False
    
    def stop_all_labs(self) -> Dict:
        """Stop all active labs"""
        results = {"stopped": [], "failed": []}
        
        for lab_id in list(self.active_labs.keys()):
            if self.stop_lab(lab_id):
                results["stopped"].append(lab_id)
            else:
                results["failed"].append(lab_id)
        
        return results
    
    def get_lab_status(self, lab_id: str) -> Optional[Dict]:
        """Get status of deployed lab"""
        if lab_id in self.active_labs:
            status = self._get_container_status(lab_id)
            ip = self._get_container_ip(lab_id)
            self.active_labs[lab_id]["status"] = status
            self.active_labs[lab_id]["ip"] = ip
            return self.active_labs[lab_id]
        return None
    
    def list_active_labs(self) -> List[Dict]:
        """List all active labs"""
        # Update status for all active labs
        for lab_id in list(self.active_labs.keys()):
            self.get_lab_status(lab_id)
        
        return list(self.active_labs.values())
    
    def get_lab_by_tag(self, tag: str) -> List[Dict]:
        """Get labs by tag"""
        return [lab for lab in self.list_active_labs() if tag in lab.get("tags", [])]
    
    def get_available_labs(self) -> List[Dict]:
        """List all available lab templates"""
        return [
            {
                "name": name,
                "description": info["description"],
                "difficulty": info["difficulty"],
                "tags": info["tags"],
                "image": info["image"]
            }
            for name, info in self.available_images.items()
        ]
    
    def get_lab_network(self) -> Dict:
        """Get network information about lab environment"""
        try:
            network_info = self._run_docker_command("network inspect redteam-lab-net")
            return {"network": "redteam-lab-net", "info": json.loads(network_info)}
        except:
            return {"error": "Network not found"}
    
    def scan_lab_network(self) -> List[Dict]:
        """Scan the lab network for active hosts"""
        hosts = []
        
        for lab_id, lab_info in self.active_labs.items():
            if lab_info.get("ip"):
                hosts.append({
                    "lab_id": lab_id,
                    "name": lab_info["name"],
                    "ip": lab_info["ip"],
                    "ports": lab_info.get("ports", {})
                })
        
        return hosts
    
    def reset_lab(self, lab_id: str) -> bool:
        """Reset a lab to its initial state"""
        if lab_id not in self.active_labs:
            return False
        
        lab_config = self.active_labs[lab_id]
        
        # Stop and remove
        self.stop_lab(lab_id)
        
        # Redeploy with same config
        new_lab = self.deploy_lab(lab_config["name"], lab_config.get("config"))
        
        return new_lab.get("status") == "running"
    
    def _create_network(self, network_name: str):
        """Create Docker network if not exists"""
        try:
            self._run_docker_command(f"network create {network_name}")
            logger.info(f"Network created: {network_name}")
        except:
            # Network already exists
            pass
    
    def _run_docker_command(self, cmd: str) -> str:
        """Run docker command and return output"""
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0 and "already exists" not in result.stderr:
            logger.warning(f"Docker command failed: {result.stderr}")
        
        return result.stdout if result.stdout else result.stderr
    
    def _get_container_status(self, container_name: str) -> str:
        """Get container status"""
        try:
            output = self._run_docker_command(f"ps -f name={container_name} --format '{{.Status}}'")
            if "Up" in output:
                return "running"
            elif "Exited" in output:
                return "stopped"
            else:
                return "unknown"
        except:
            return "unknown"
    
    def _get_container_ip(self, container_name: str) -> Optional[str]:
        """Get container IP address"""
        try:
            output = self._run_docker_command(
                f"inspect -f '{{{{range.NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {container_name}"
            )
            return output.strip() if output.strip() else None
        except:
            return None
    
    def execute_in_lab(self, lab_id: str, command: str) -> Dict:
        """Execute a command inside a lab container"""
        if lab_id not in self.active_labs:
            return {"error": "Lab not found"}
        
        try:
            cmd = f"exec {lab_id} {command}"
            output = self._run_docker_command(cmd)
            return {
                "success": True,
                "output": output,
                "lab_id": lab_id
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "lab_id": lab_id
            }


# Singleton instance
lab_deployer = LabDeployer()