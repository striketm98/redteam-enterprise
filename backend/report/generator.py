"""
Report Generator - Main report generation engine
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from .exporters.pdf_exporter import PDFExporter
from .exporters.html_exporter import HTMLExporter
from .exporters.json_exporter import JSONExporter
from .exporters.csv_exporter import CSVExporter


class ReportGenerator:
    """Main report generation engine"""
    
    def __init__(self):
        self.reports_dir = '/app/reports'
        os.makedirs(self.reports_dir, exist_ok=True)
        
        self.pdf_exporter = PDFExporter()
        self.html_exporter = HTMLExporter()
        self.json_exporter = JSONExporter()
        self.csv_exporter = CSVExporter()
        
        self.report_history = []
    
    def generate_report(self, scans: List[Dict], report_type: str, username: str) -> Dict:
        """Generate a comprehensive security report"""
        
        report_data = {
            'title': self._get_report_title(report_type),
            'generated_by': username,
            'generated_at': datetime.now().isoformat(),
            'report_type': report_type,
            'executive_summary': self._generate_executive_summary(scans),
            'findings': self._aggregate_findings(scans),
            'statistics': self._calculate_statistics(scans),
            'technical_details': self._generate_technical_details(scans),
            'recommendations': self._generate_recommendations(scans),
            'appendix': self._generate_appendix(scans)
        }
        
        # Store in history
        report_id = f"REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.report_history.append({
            'id': report_id,
            'type': report_type,
            'generated_at': report_data['generated_at'],
            'generated_by': username
        })
        
        return report_data
    
    def export_pdf(self, report_data: Dict, filename: str = None) -> str:
        """Export report as PDF"""
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        filepath = os.path.join(self.reports_dir, filename)
        return self.pdf_exporter.export(report_data, filepath)
    
    def export_html(self, report_data: Dict, filename: str = None) -> str:
        """Export report as HTML"""
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        filepath = os.path.join(self.reports_dir, filename)
        return self.html_exporter.export(report_data, filepath)
    
    def export_json(self, report_data: Dict, filename: str = None) -> str:
        """Export report as JSON"""
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.reports_dir, filename)
        return self.json_exporter.export(report_data, filepath)
    
    def export_csv(self, findings: List[Dict], filename: str = None) -> str:
        """Export findings as CSV"""
        if not filename:
            filename = f"findings_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = os.path.join(self.reports_dir, filename)
        return self.csv_exporter.export(findings, filepath)
    
    def _get_report_title(self, report_type: str) -> str:
        """Get report title based on type"""
        titles = {
            'executive': 'Executive Summary Security Assessment Report',
            'technical': 'Technical Security Assessment Report',
            'full': 'Comprehensive Security Assessment Report',
            'summary': 'Security Assessment Summary Report',
            'compliance': 'Compliance Security Assessment Report'
        }
        return titles.get(report_type, 'Security Assessment Report')
    
    def _generate_executive_summary(self, scans: List[Dict]) -> Dict:
        """Generate executive summary section"""
        total_findings = sum(len(s.get('findings', [])) for s in scans)
        critical = sum(1 for s in scans for f in s.get('findings', []) if f.get('severity') == 'Critical')
        high = sum(1 for s in scans for f in s.get('findings', []) if f.get('severity') == 'High')
        medium = sum(1 for s in scans for f in s.get('findings', []) if f.get('severity') == 'Medium')
        
        risk_level = self._calculate_risk_level(critical, high)
        
        return {
            'overall_risk': risk_level,
            'total_targets': len(scans),
            'total_findings': total_findings,
            'critical_findings': critical,
            'high_findings': high,
            'medium_findings': medium,
            'summary_text': self._generate_summary_text(risk_level, critical, high, total_findings),
            'key_recommendations': self._get_key_recommendations(risk_level)
        }
    
    def _aggregate_findings(self, scans: List[Dict]) -> List[Dict]:
        """Aggregate findings from all scans"""
        all_findings = []
        for scan in scans:
            for finding in scan.get('findings', []):
                finding['source_target'] = scan.get('target')
                finding['source_scan_type'] = scan.get('scan_type')
                finding['source_date'] = scan.get('created_at')
                all_findings.append(finding)
        
        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'Low'), 5))
        
        return all_findings
    
    def _calculate_statistics(self, scans: List[Dict]) -> Dict:
        """Calculate report statistics"""
        findings = self._aggregate_findings(scans)
        
        stats = {
            'total_scans': len(scans),
            'total_findings': len(findings),
            'critical': len([f for f in findings if f.get('severity') == 'Critical']),
            'high': len([f for f in findings if f.get('severity') == 'High']),
            'medium': len([f for f in findings if f.get('severity') == 'Medium']),
            'low': len([f for f in findings if f.get('severity') == 'Low']),
            'info': len([f for f in findings if f.get('severity') == 'Info']),
            'unique_targets': len(set([s.get('target') for s in scans])),
            'scan_types': list(set([s.get('scan_type') for s in scans])),
            'risk_score': self._calculate_risk_score(findings)
        }
        
        # Calculate percentages
        if stats['total_findings'] > 0:
            stats['critical_percentage'] = round((stats['critical'] / stats['total_findings']) * 100, 1)
            stats['high_percentage'] = round((stats['high'] / stats['total_findings']) * 100, 1)
        
        return stats
    
    def _generate_technical_details(self, scans: List[Dict]) -> Dict:
        """Generate technical details section"""
        technical = {
            'scan_details': [],
            'vulnerability_breakdown': {},
            'port_statistics': {},
            'service_enumeration': []
        }
        
        for scan in scans:
            # Scan details
            technical['scan_details'].append({
                'target': scan.get('target'),
                'scan_type': scan.get('scan_type'),
                'scan_date': scan.get('created_at'),
                'status': scan.get('status'),
                'findings_count': len(scan.get('findings', [])),
                'duration': scan.get('duration', 'N/A')
            })
            
            # Port statistics
            open_ports = scan.get('results', {}).get('open_ports', [])
            for port in open_ports:
                if port not in technical['port_statistics']:
                    technical['port_statistics'][port] = 0
                technical['port_statistics'][port] += 1
        
        return technical
    
    def _generate_recommendations(self, scans: List[Dict]) -> List[Dict]:
        """Generate remediation recommendations"""
        findings = self._aggregate_findings(scans)
        critical_findings = [f for f in findings if f.get('severity') == 'Critical']
        high_findings = [f for f in findings if f.get('severity') == 'High']
        
        recommendations = []
        
        # Immediate actions
        if critical_findings:
            recommendations.append({
                'priority': 'Critical',
                'timeline': '24 hours',
                'actions': [
                    'Patch all critical vulnerabilities immediately',
                    'Isolate affected systems if patches unavailable',
                    'Conduct incident response investigation',
                    'Implement temporary compensating controls'
                ]
            })
        
        if high_findings:
            recommendations.append({
                'priority': 'High',
                'timeline': '7 days',
                'actions': [
                    'Remediate high-severity vulnerabilities',
                    'Review and update security configurations',
                    'Enhance monitoring for affected services'
                ]
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'Medium',
            'timeline': '30 days',
            'actions': [
                'Implement regular patch management schedule',
                'Conduct security awareness training',
                'Review and update incident response plan',
                'Implement principle of least privilege'
            ]
        })
        
        recommendations.append({
            'priority': 'Ongoing',
            'timeline': 'Continuous',
            'actions': [
                'Conduct regular security assessments',
                'Implement continuous monitoring',
                'Maintain asset inventory',
                'Review security policies annually'
            ]
        })
        
        return recommendations
    
    def _generate_appendix(self, scans: List[Dict]) -> Dict:
        """Generate appendix section"""
        return {
            'scan_configurations': [
                {
                    'scan_id': s.get('id'),
                    'target': s.get('target'),
                    'scan_type': s.get('scan_type'),
                    'command': s.get('results', {}).get('command', 'N/A'),
                    'timestamp': s.get('created_at')
                }
                for s in scans
            ],
            'methodology': self._get_methodology(),
            'risk_matrix': self._get_risk_matrix(),
            'references': self._get_references()
        }
    
    def _calculate_risk_level(self, critical: int, high: int) -> str:
        """Calculate overall risk level"""
        if critical > 0:
            return 'Critical'
        elif high > 2:
            return 'High'
        elif high > 0:
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        """Calculate numerical risk score (0-100)"""
        if not findings:
            return 0
        
        weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 1}
        total = sum(weights.get(f.get('severity', 'Low'), 1) for f in findings)
        max_score = len(findings) * 10
        
        return round((total / max_score) * 100) if max_score > 0 else 0
    
    def _generate_summary_text(self, risk_level: str, critical: int, high: int, total: int) -> str:
        """Generate executive summary text"""
        if risk_level == 'Critical':
            return f"This assessment identified {critical} critical and {high} high-severity vulnerabilities that pose an immediate risk to the organization. These issues require urgent remediation to prevent potential compromise."
        elif risk_level == 'High':
            return f"The assessment found {critical} critical and {high} high-severity vulnerabilities. While no immediate critical issues were found, these vulnerabilities could lead to significant security incidents if not addressed."
        elif risk_level == 'Medium':
            return f"Security assessment identified {total} vulnerabilities requiring remediation. None are critical, but addressing medium and high issues is recommended."
        else:
            return f"Assessment completed with {total} findings. No critical or high-severity vulnerabilities were identified. Standard security maintenance is recommended."
    
    def _get_key_recommendations(self, risk_level: str) -> List[str]:
        """Get key recommendations based on risk level"""
        recommendations = {
            'Critical': [
                'Immediately patch critical vulnerabilities',
                'Implement emergency security controls',
                'Conduct full incident response review'
            ],
            'High': [
                'Prioritize remediation of high-severity findings',
                'Review security configurations',
                'Enhance monitoring capabilities'
            ],
            'Medium': [
                'Address vulnerabilities in next sprint',
                'Review and update security policies',
                'Schedule follow-up assessment'
            ],
            'Low': [
                'Follow standard patch management',
                'Maintain regular security monitoring',
                'Document findings for continuous improvement'
            ]
        }
        return recommendations.get(risk_level, recommendations['Low'])
    
    def _get_methodology(self) -> str:
        """Get assessment methodology"""
        return """
        The security assessment was conducted using the following methodology:
        
        1. Reconnaissance: Passive information gathering about target infrastructure
        2. Scanning: Active port and service enumeration using industry-standard tools
        3. Vulnerability Assessment: Identification of known vulnerabilities using automated scanners
        4. Exploitation: Attempted exploitation of identified vulnerabilities (in isolated environment)
        5. Post-Exploitation: Assessment of potential impact and lateral movement
        6. Reporting: Documentation of findings with remediation guidance
        
        Tools used include Nmap, Metasploit, Gobuster, Nikto, and custom scripts.
        """
    
    def _get_risk_matrix(self) -> Dict:
        """Get risk matrix definition"""
        return {
            'Critical': {'score': '9.0-10.0', 'description': 'Immediate threat, likely exploitation'},
            'High': {'score': '7.0-8.9', 'description': 'Significant risk, probable exploitation'},
            'Medium': {'score': '4.0-6.9', 'description': 'Moderate risk, possible exploitation'},
            'Low': {'score': '0.1-3.9', 'description': 'Minor risk, unlikely exploitation'},
            'Info': {'score': '0.0', 'description': 'Informational only, no direct risk'}
        }
    
    def _get_references(self) -> List[str]:
        """Get security references"""
        return [
            'OWASP Top 10 - https://owasp.org/Top10/',
            'NIST Cybersecurity Framework - https://www.nist.gov/cyberframework',
            'CWE Top 25 - https://cwe.mitre.org/top25/',
            'PTES Technical Guidelines - http://www.pentest-standard.org/'
        ]


# Singleton instance
report_generator = ReportGenerator()