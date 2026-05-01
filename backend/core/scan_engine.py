import subprocess
import json
import re
from datetime import datetime
from typing import Dict, List, Any

class ScanEngine:
    """Comprehensive scanning engine with multiple tool integration"""
    
    def __init__(self):
        self.scan_results = {}
    
    def quick_scan(self, target: str) -> Dict:
        """Quick scan for common ports and services"""
        results = {
            'target': target,
            'scan_type': 'quick',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'raw_output': {}
        }
        
        # Nmap quick scan
        try:
            cmd = f"nmap -F -sV {target}"
            output = self._run_command(cmd)
            results['raw_output']['nmap'] = output
            results['open_ports'] = self._parse_nmap_ports(output)
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def full_scan(self, target: str) -> Dict:
        """Comprehensive full scan with all tools"""
        results = {
            'target': target,
            'scan_type': 'full',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'raw_output': {},
            'scans': {}
        }
        
        # 1. Full port scan
        results['scans']['full_port'] = self._run_command(f"nmap -p- -sV -sC -O {target}")
        
        # 2. Vulnerability scan
        results['scans']['vuln'] = self._run_command(f"nmap --script vuln {target}")
        
        # 3. UDP scan
        results['scans']['udp'] = self._run_command(f"nmap -sU --top-ports 100 {target}")
        
        # 4. Web scan if web ports found
        if self._has_web_ports(results['scans']['full_port']):
            results['scans']['nikto'] = self._run_command(f"nikto -h http://{target} -Format json")
            results['scans']['gobuster'] = self._run_command(f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 50")
        
        # 5. Generate findings
        results['findings'] = self._generate_comprehensive_findings(results)
        
        return results
    
    def web_scan(self, target: str) -> Dict:
        """Web application focused scan"""
        results = {
            'target': target,
            'scan_type': 'web',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'raw_output': {}
        }
        
        # Run web-specific tools
        results['raw_output']['whatweb'] = self._run_command(f"whatweb http://{target}")
        results['raw_output']['wpscan'] = self._run_command(f"wpscan --url http://{target} --enumerate")
        
        return results
    
    def network_scan(self, target: str) -> Dict:
        """Network-focused scan (CIDR ranges)"""
        results = {
            'target': target,
            'scan_type': 'network',
            'timestamp': datetime.now().isoformat(),
            'hosts': [],
            'findings': []
        }
        
        # Network discovery
        output = self._run_command(f"nmap -sn {target}")
        results['live_hosts'] = self._parse_live_hosts(output)
        
        for host in results['live_hosts']:
            host_scan = self._run_command(f"nmap -sV {host}")
            results['hosts'].append({
                'ip': host,
                'scan': host_scan
            })
        
        return results
    
    def custom_scan(self, target: str, options: Dict) -> Dict:
        """Custom scan with user-provided options"""
        cmd = f"nmap {options.get('flags', '-sV')} {target}"
        output = self._run_command(cmd)
        
        return {
            'target': target,
            'scan_type': 'custom',
            'command': cmd,
            'output': output,
            'timestamp': datetime.now().isoformat()
        }
    
    def generate_findings(self, results: Dict) -> List[Dict]:
        """Generate security findings from scan results"""
        findings = []
        
        # Check for critical ports
        critical_ports = {
            21: 'FTP - Clear text authentication',
            23: 'Telnet - Unencrypted communication',
            445: 'SMB - Potential for EternalBlue',
            3389: 'RDP - Potential for BlueKeep',
            5900: 'VNC - Weak authentication'
        }
        
        for port, description in critical_ports.items():
            if port in results.get('open_ports', []):
                findings.append({
                    'title': f'Critical Service Exposed on Port {port}',
                    'severity': 'Critical',
                    'description': f'Port {port} is open. {description}',
                    'remediation': f'Restrict access to port {port} using firewall rules and implement strong authentication.',
                    'cvss_score': 9.0
                })
        
        # Check for web vulnerabilities
        if 'nikto' in results.get('raw_output', {}):
            nikto_output = results['raw_output']['nikto']
            if 'vulnerable' in nikto_output.lower():
                findings.append({
                    'title': 'Web Vulnerabilities Detected',
                    'severity': 'High',
                    'description': 'Nikto scan identified potential web vulnerabilities',
                    'remediation': 'Run detailed web application security assessment',
                    'cvss_score': 7.5
                })
        
        return findings
    
    def _run_command(self, cmd: str) -> str:
        """Execute shell command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            return result.stdout
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _parse_nmap_ports(self, output: str) -> List[int]:
        """Parse open ports from nmap output"""
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                port_match = re.search(r'(\d+)/tcp', line)
                if port_match:
                    ports.append(int(port_match.group(1)))
        return ports
    
    def _parse_live_hosts(self, output: str) -> List[str]:
        """Parse live hosts from nmap discovery"""
        hosts = []
        for line in output.split('\n'):
            if 'Nmap scan report for' in line:
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if ip_match:
                    hosts.append(ip_match.group())
        return hosts
    
    def _has_web_ports(self, output: str) -> bool:
        """Check if web ports are open"""
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        open_ports = self._parse_nmap_ports(output)
        return any(port in web_ports for port in open_ports)
    
    def _generate_comprehensive_findings(self, results: Dict) -> List[Dict]:
        """Generate comprehensive findings from all scan data"""
        findings = []
        
        # OS detection
        if 'OS details' in results.get('scans', {}).get('full_port', ''):
            findings.append({
                'title': 'Operating System Identified',
                'severity': 'Info',
                'description': 'OS fingerprinting successful, making targeted attacks easier',
                'remediation': 'Use network hardening and consider OS obfuscation'
            })
        
        # Open ports count
        open_ports = self._parse_nmap_ports(results.get('scans', {}).get('full_port', ''))
        if len(open_ports) > 100:
            findings.append({
                'title': 'Excessive Open Ports',
                'severity': 'Medium',
                'description': f'Found {len(open_ports)} open ports, increasing attack surface',
                'remediation': 'Close unnecessary ports using firewall rules'
            })
        
        return findings
