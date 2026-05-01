"""
Task Runner - Secure command execution and task management
"""

import subprocess
import asyncio
import logging
import shlex
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from threading import Lock

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TaskRunner:
    """Secure task execution engine with safety controls"""
    
    def __init__(self):
        self.task_history = []
        self.active_tasks = {}
        self.task_lock = Lock()
        
        # Safe command whitelist
        self.safe_commands = [
            "nmap", "gobuster", "nikto", "whatweb", "enum4linux", 
            "smbclient", "crackmapexec", "hydra", "sqlmap", "whois",
            "dig", "nslookup", "ping", "traceroute", "curl", "wget"
        ]
        
        # Dangerous patterns (blocked)
        self.dangerous_patterns = [
            "rm -rf", "dd if=", "mkfs", ":(){ :|:& };:", 
            "chmod 777 /", "> /dev/sda", "fork bomb",
            "mkfs.ext4", "format", "del /f", "rd /s"
        ]
    
    async def run_command(self, command: str, timeout: int = 60, task_id: str = None) -> Dict:
        """Execute a command safely with timeout"""
        if not task_id:
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
        
        with self.task_lock:
            self.active_tasks[task_id] = result
        
        try:
            # Validate command
            if not self._is_safe_command(command):
                result["status"] = "blocked"
                result["error"] = "Command blocked for security reasons"
                result["duration"] = 0
                logger.warning(f"Blocked dangerous command: {command}")
                return result
            
            # Execute command
            start_time = datetime.now()
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                executable='/bin/bash'
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                result["output"] = stdout.decode('utf-8', errors='ignore')[:50000]  # Limit output size
                result["error"] = stderr.decode('utf-8', errors='ignore')[:10000]
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
        
        with self.task_lock:
            self.task_history.append(result)
            if task_id in self.active_tasks:
                del self.active_tasks[task_id]
        
        return result
    
    def _is_safe_command(self, command: str) -> bool:
        """Check if command is safe to execute"""
        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if pattern in command.lower():
                return False
        
        # Check if command starts with a safe tool
        first_word = command.split()[0].lower() if command.split() else ""
        
        # Allow file operations in /tmp directory
        if first_word in ["cat", "less", "more", "head", "tail"] and "/tmp" in command:
            return True
        
        # Check against safe commands list
        if first_word in self.safe_commands:
            return True
        
        # Allow echo and pipe commands (with caution)
        if first_word in ["echo", "grep", "awk", "sed", "sort", "uniq", "wc"]:
            return True
        
        # Special case for nmap (allow but with restrictions)
        if first_word == "nmap" and "--script" not in command:
            return True
        
        return False
    
    async def run_enumeration(self, target: str, ports: List[int] = None) -> Dict:
        """Run comprehensive enumeration against target"""
        results = {}
        
        # Quick port scan
        port_scan = await self.run_command(f"nmap -F --min-rate 1000 {target}", timeout=120)
        results["port_scan"] = port_scan
        
        # Parse open ports
        open_ports = self._parse_open_ports(port_scan.get("output", ""))
        
        if open_ports:
            # Service version scan
            ports_str = ",".join(map(str, open_ports[:20]))
            service_scan = await self.run_command(f"nmap -sV -sC -p {ports_str} {target}", timeout=180)
            results["service_scan"] = service_scan
        
        # Web enumeration if web ports present
        web_ports = [80, 443, 8080, 8443, 8000]
        if any(str(port) in port_scan.get("output", "") for port in web_ports):
            web_scan = await self.run_command(
                f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 50 -q",
                timeout=180
            )
            results["web_scan"] = web_scan
        
        return results
    
    def _parse_open_ports(self, output: str) -> List[int]:
        """Parse open ports from nmap output"""
        import re
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                match = re.search(r'(\d+)/tcp', line)
                if match:
                    ports.append(int(match.group(1)))
        return ports
    
    async def run_exploit(self, exploit_name: str, target: str, options: Dict = None) -> Dict:
        """Run specific exploit against target"""
        exploits = {
            "ssh_bruteforce": f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{target} -t 4",
            "smb_enum": f"enum4linux -a {target}",
            "web_dirbust": f"dirb http://{target}",
            "nmap_vuln": f"nmap --script vuln {target}"
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
        with self.task_lock:
            return self.active_tasks.get(task_id)
    
    def cancel_task(self, task_id: str) -> bool:
        """Attempt to cancel running task"""
        with self.task_lock:
            if task_id in self.active_tasks:
                logger.info(f"Task {task_id} cancellation requested")
                # Note: Actual process cancellation would require storing process handles
                return True
        return False
    
    def get_statistics(self) -> Dict