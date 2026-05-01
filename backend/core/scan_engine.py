import subprocess
import json
import re
import nmap
from datetime import datetime
from typing import Dict, List, Any

class ScanEngine:
    """Comprehensive scanning engine with multiple tools"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def run_nmap_scan(self, target: str, scan_type: str = 'full') -> Dict:
        """Run Nmap scan with various options"""
        results = {
            'tool': 'nmap',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'findings': []
        }
        
        try:
            if scan_type == 'quick':
                arguments = '-F'  # Fast scan
            elif scan_type == 'ports':
                arguments = '-p- --min-rate 1000'  # All ports
            elif scan_type == 'services':
                arguments = '-sV -sC -O'  # Service version and OS detection
            else:  # full
                arguments = '-sV -sC -O -p- --min-rate 1000'
            
            self.nm.scan(target, arguments=arguments)
            
            for host in self.nm.all_hosts():
                host_info = {
                    'host': host,
                    'status': self.nm[host].state(),
                    'hostname': self.nm[host].hostname(),
                    'ports': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        port_info = {
                            'port': port,
                            'protocol': proto,
                            'service': service.get('name', 'unknown'),
                            'version': service.get('version', ''),
                            'state': service.get('state', 'unknown')
                        }
                        host_info['ports'].append(port_info)
                        
                        # Generate findings for open ports
                        finding = self._analyze_port(port, port_info['service'])
                        if finding:
                            results['findings'].append(finding)
                
                results['hosts'] = results.get('hosts', [])
                results['hosts'].append(host_info)
            
            results['status'] = 'completed'
            
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = str(e)
        
        return results
    
    def run_gobuster_scan(self, target: str) -> Dict:
        """Run directory brute-forcing with gobuster"""
        results = {
            'tool': 'gobuster',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'directories': [],
            'findings': []
        }
        
        try:
            cmd = f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 30 -q -o /tmp/gobuster_results.txt"
            subprocess.run(cmd, shell=True, timeout=120, capture_output=True)
            
            with open('/tmp/gobuster_results.txt', 'r') as f:
                for line in f:
                    if 'Status:' in line:
                        results['directories'].append(line.strip())
                        
                        # Generate finding for interesting directories
                        if 'admin' in line.lower() or 'login' in line.lower():
                            results['findings'].append({
                                'title': f'Potentially Sensitive Directory Found',
                                'severity': 'Medium',
                                'description': f'Directory discovered: {line.strip()}',
                                'remediation': 'Restrict access or remove if not needed'
                            })
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def run_nikto_scan(self, target: str) -> Dict:
        """Run web vulnerability scanner"""
        results = {
            'tool': 'nikto',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'findings': []
        }
        
        try:
            cmd = f"nikto -h http://{target} -Format json -output /tmp/nikto_results.json"
            subprocess.run(cmd, shell=True, timeout=300, capture_output=True)
            
            with open('/tmp/nikto_results.json', 'r') as f:
                data = json.load(f)
                for vuln in data.get('vulnerabilities', []):
                    results['vulnerabilities'].append(vuln)
                    results['findings'].append({
                        'title': vuln.get('name', 'Web Vulnerability'),
                        'severity': self._map_nikto_severity(vuln.get('severity', 0)),
                        'description': vuln.get('description', ''),
                        'remediation': vuln.get('solution', 'Apply security patches')
                    })
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def run_full_assessment(self, target: str) -> Dict:
        """Run complete security assessment with all tools"""
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scans': {},
            'all_findings': []
        }
        
        # Run all scans
        results['scans']['nmap'] = self.run_nmap_scan(target, 'full')
        results['scans']['gobuster'] = self.run_gobuster_scan(target)
        results['scans']['nikto'] = self.run_nikto_scan(target)
        
        # Aggregate findings
        for scan_name, scan_results in results['scans'].items():
            for finding in scan_results.get('findings', []):
                finding['source_scan'] = scan_name
                results['all_findings'].append(finding)
        
        return results
    
    def _analyze_port(self, port: int, service: str) -> Dict:
        """Analyze open port and generate findings"""
        critical_ports = {
            21: 'FTP - Clear text authentication',
            23: 'Telnet - Unencrypted communication',
            445: 'SMB - Potential for EternalBlue',
            3389: 'RDP - Potential for BlueKeep',
            5900: 'VNC - Weak authentication possible'
        }
        
        high_ports = {
            22: 'SSH - Ensure key-based auth only',
            3306: 'MySQL - Default credentials possible',
            5432: 'PostgreSQL - Default credentials possible',
            27017: 'MongoDB - No authentication default'
        }
        
        if port in critical_ports:
            return {
                'title': f'Critical Service Exposed - {service.upper()}',
                'severity': 'Critical',
                'description': f'Port {port} is running {service}. {critical_ports[port]}',
                'remediation': f'Restrict access to port {port} using firewall rules'
            }
        elif port in high_ports:
            return {
                'title': f'High Risk Service - {service.upper()}',
                'severity': 'High',
                'description': f'Port {port} is running {service}. {high_ports[port]}',
                'remediation': f'Apply security best practices for {service}'
            }
        
        return None
    
    def _map_nikto_severity(self, nikto_severity: int) -> str:
        """Map Nikto severity to standard levels"""
        if nikto_severity >= 2:
            return 'High'
        elif nikto_severity >= 1:
            return 'Medium'
        else:
            return 'Low'
