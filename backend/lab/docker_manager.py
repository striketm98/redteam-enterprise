"""
Docker Manager - Low-level Docker operations for lab management
"""

import subprocess
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class DockerManager:
    """Manage Docker containers, images, and networks for labs"""
    
    def __init__(self):
        self.docker_available = self._check_docker()
    
    def _check_docker(self) -> bool:
        """Check if Docker is available"""
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def list_containers(self, all_containers: bool = False) -> List[Dict]:
        """List Docker containers"""
        if not self.docker_available:
            return []
        
        cmd = "docker ps -a" if all_containers else "docker ps"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        containers = []
        lines = result.stdout.strip().split('\n')[1:]  # Skip header
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 7:
                containers.append({
                    "id": parts[0],
                    "image": parts[1],
                    "command": parts[2],
                    "created": parts[3],
                    "status": " ".join(parts[4:6]),
                    "name": parts[-1]
                })
        
        return containers
    
    def get_container_details(self, container_id: str) -> Optional[Dict]:
        """Get detailed information about a container"""
        if not self.docker_available:
            return None
        
        cmd = f"docker inspect {container_id}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if data:
                return data[0]
        return None
    
    def pull_image(self, image_name: str) -> bool:
        """Pull a Docker image"""
        if not self.docker_available:
            return False
        
        try:
            cmd = f"docker pull {image_name}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to pull image {image_name}: {e}")
            return False
    
    def list_images(self) -> List[Dict]:
        """List Docker images"""
        if not self.docker_available:
            return []
        
        cmd = "docker images --format json"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        images = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    images.append(json.loads(line))
                except:
                    pass
        
        return images
    
    def create_network(self, network_name: str, driver: str = "bridge") -> bool:
        """Create a Docker network"""
        if not self.docker_available:
            return False
        
        try:
            cmd = f"docker network create --driver {driver} {network_name}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to create network: {e}")
            return False
    
    def remove_network(self, network_name: str) -> bool:
        """Remove a Docker network"""
        if not self.docker_available:
            return False
        
        try:
            cmd = f"docker network rm {network_name}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to remove network: {e}")
            return False
    
    def list_networks(self) -> List[Dict]:
        """List Docker networks"""
        if not self.docker_available:
            return []
        
        cmd = "docker network ls"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        networks = []
        lines = result.stdout.strip().split('\n')[1:]  # Skip header
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                networks.append({
                    "id": parts[0],
                    "name": parts[1],
                    "driver": parts[2]
                })
        
        return networks
    
    def get_container_logs(self, container_id: str, lines: int = 100) -> str:
        """Get container logs"""
        if not self.docker_available:
            return ""
        
        cmd = f"docker logs --tail {lines} {container_id}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        return result.stdout
    
    def stop_container(self, container_id: str) -> bool:
        """Stop a container"""
        if not self.docker_available:
            return False
        
        try:
            cmd = f"docker stop {container_id}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def start_container(self, container_id: str) -> bool:
        """Start a container"""
        if not self.docker_available:
            return False
        
        try:
            cmd = f"docker start {container_id}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def remove_container(self, container_id: str, force: bool = False) -> bool:
        """Remove a container"""
        if not self.docker_available:
            return False
        
        try:
            cmd = f"docker rm {'-f' if force else ''} {container_id}".strip()
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def get_resource_usage(self) -> Dict:
        """Get Docker resource usage statistics"""
        if not self.docker_available:
            return {}
        
        try:
            cmd = "docker stats --no-stream --format json"
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
            stats = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        stats.append(json.loads(line))
                    except:
                        pass
            
            return {
                "containers": stats,
                "total_containers": len(stats)
            }
        except:
            return {}


# Singleton instance
docker_manager = DockerManager()