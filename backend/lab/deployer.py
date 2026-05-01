import subprocess
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LabDeployer:
    def __init__(self):
        self.active_labs = {}
        self.available_images = {
            "web_dvwa": "vulnerables/web-dvwa",
            "web_juice_shop": "bkimminich/juice-shop",
            "web_wordpress": "wordpress:latest",
            "ssh_weak": "vulnerables/ssh-weak",
            "smb_vuln": "ismailshak/prettyeasyctf",
            "metasploitable": "tleemcjr/metasploitable2"
        }
    
    def deploy_lab(self, lab_name: str, config: Dict = None) -> Dict:
        """Deploy a lab environment"""
        if lab_name not in self.available_images:
            return {"error": f"Unknown lab: {lab_name}"}
        
        lab_id = f"{lab_name}_{int(time.time())}"
        
        try:
            # Create network if not exists
            self._run_docker_command("network create redteam-net 2>/dev/null || true")
            
            # Deploy container
            cmd = f"docker run -d --name {lab_id} --network redteam-net"
            
            # Add port mappings
            if config and "ports" in config:
                for host_port, container_port in config["ports"].items():
                    cmd += f" -p {host_port}:{container_port}"
            
            cmd += f" {self.available_images[lab_name]}"
            
            output = self._run_docker_command(cmd)
            
            lab_info = {
                "lab_id": lab_id,
                "name": lab_name,
                "image": self.available_images[lab_name],
                "status": "deploying",
                "created": datetime.now().isoformat(),
                "config": config or {},
                "container_id": output.strip()
            }
            
            # Wait for container to be ready
            time.sleep(5)
            lab_info["status"] = self._get_container_status(lab_id)
            
            self.active_labs[lab_id] = lab_info
            logger.info(f"Lab deployed: {lab_name} ({lab_id})")
            
            return lab_info
            
        except Exception as e:
            logger.error(f"Failed to deploy lab: {e}")
            return {"error": str(e)}
    
    def deploy_multi_target(self, targets: List[Dict]) -> List[Dict]:
        """Deploy multiple targets for lateral movement practice"""
        results = []
        
        for target_config in targets:
            result = self.deploy_lab(
                target_config["name"],
                {"ports": target_config.get("ports", {})}
            )
            results.append(result)
        
        logger.info(f"Deployed {len(results)} targets")
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
    
    def get_lab_status(self, lab_id: str) -> Optional[Dict]:
        """Get status of deployed lab"""
        if lab_id in self.active_labs:
            status = self._get_container_status(lab_id)
            self.active_labs[lab_id]["status"] = status
            return self.active_labs[lab_id]
        return None
    
    def list_active_labs(self) -> List[Dict]:
        """List all active labs"""
        return list(self.active_labs.values())
    
    def get_lab_network(self) -> Dict:
        """Get network information about lab environment"""
        try:
            output = self._run_docker_command("network inspect redteam-net")
            return {"network": "redteam-net", "info": output}
        except:
            return {"error": "Network not found"}
    
    def _run_docker_command(self, cmd: str) -> str:
        """Run docker command and return output"""
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            logger.warning(f"Docker command failed: {result.stderr}")
            return result.stderr
        
        return result.stdout
    
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
    
    def available_labs(self) -> List[str]:
        """List all available lab templates"""
        return list(self.available_images.keys())