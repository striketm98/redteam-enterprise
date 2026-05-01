import subprocess
import asyncio
import logging
import shlex
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TaskRunner:
    def __init__(self):
        self.task_history = []
        self.active_tasks = {}
        self.safe_commands = [
            "nmap", "gobuster", "nikto", "whatweb",
            "enum4linux", "smbclient", "crackmapexec"
        ]
    
    async def run_command(self, command: str, timeout: int = 60) -> Dict:
        """Execute a command safely with timeout"""
        task_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        
        result = {
            "task_id": task_id,
            "command": command,
            "status": "running",
            "output": "",
            "error": "",
            "duration": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        self.active_tasks[task_id] = result
        
        try:
            # Sanitize command
            safe_cmd = self._sanitize_command(command)
            
            # Execute command
            start_time = datetime.now()
            process = await asyncio.create_subprocess_shell(
                safe_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                result["output"] = stdout.decode('utf-8', errors='ignore')
                result["error"] = stderr.decode('utf-8', errors='ignore')
                result["returncode"] = process.returncode
                result["status"] = "completed" if process.returncode == 0 else "failed"
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                result["status"] = "timeout"
                result["error"] = f"Command timed out after {timeout} seconds"
            
            result["duration"] = (datetime.now() - start_time).total_seconds()
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Command execution error: {e}")
        
        self.task_history.append(result)
        del self.active_tasks[task_id]
        
        return result
    
    def _sanitize_command(self, command: str) -> str:
        """Sanitize command for safe execution"""
        # Remove dangerous operations
        dangerous_patterns = [
            "rm -rf", "dd if=", "mkfs", ":(){ :|:& };:", 
            "chmod 777 /", "> /dev/sda", "fork bomb"
        ]
        
        for pattern in dangerous_patterns:
            if pattern in command.lower():
                logger.warning(f"Dangerous command pattern detected: {pattern}")
                return f"echo 'Command blocked for safety: {pattern}'"
        
        # Ensure command is properly escaped
        return shlex.quote(command) if ' ' in command else command
    
    async def run_enumeration(self, target: str, ports: List[int] = None) -> Dict:
        """Run comprehensive enumeration against target"""
        results = {}
        
        # Basic port scan
        port_scan = await self.run_command(f"nmap -p- --min-rate 1000 {target}", timeout=120)
        results["port_scan"] = port_scan
        
        # Service version scan on open ports
        if ports:
            ports_str = ",".join(map(str, ports[:20]))  # Limit to 20 ports
            service_scan = await self.run_command(f"nmap -sV -sC -p {ports_str} {target}", timeout=180)
            results["service_scan"] = service_scan
        
        # Web enumeration if web ports are present
        web_ports = [80, 443, 8080, 8443, 8000]
        if any(str(port) in port_scan["output"] for port in web_ports):
            web_scan = await self.run_command(f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 50", timeout=180)
            results["web_scan"] = web_scan
        
        return results
    
    async def run_exploit(self, exploit_name: str, target: str, options: Dict = None) -> Dict:
        """Run specific exploit against target"""
        exploits = {
            "ssh_bruteforce": f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{target} -t 4",
            "smb_enum": f"enum4linux -a {target}",
            "web_dirbust": f"dirb http://{target}"
        }
        
        if exploit_name in exploits:
            command = exploits[exploit_name]
            if options:
                command = command.format(**options)
            return await self.run_command(command, timeout=300)
        
        return {"error": f"Unknown exploit: {exploit_name}"}
    
    def get_task_history(self, limit: int = 50) -> List[Dict]:
        """Get recent task history"""
        return self.task_history[-limit:]
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Get status of specific task"""
        return self.active_tasks.get(task_id)
    
    def cancel_task(self, task_id: str) -> bool:
        """Attempt to cancel running task"""
        if task_id in self.active_tasks:
            # Implementation would need process handle
            logger.info(f"Task {task_id} cancellation requested")
            return True
        return False