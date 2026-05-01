import json
from datetime import datetime
from typing import Dict, List, Any

class AIAnalyzer:
    """AI-powered analysis engine for security findings"""
    
    def __init__(self):
        self.severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 2,
            'Info': 1
        }
    
    def analyze_results(self, scan_results: Dict) -> Dict:
        """AI-powered analysis of scan results"""
        
        analysis = {
            'risk_score': 0,
            'summary': '',
            'prioritized_findings': [],
            'remediation_plan': [],
            'estimated_impact': '',
            'recommendations': []
        }
        
        findings = scan_results.get('findings', [])
        
        if not findings:
            analysis['summary'] = 'No significant vulnerabilities were detected in this scan.'
            analysis['risk_score'] = 0
            return analysis
        
        # Calculate risk score
        total_score = 0
        for finding in findings:
            severity = finding.get('severity', 'Low')
            total_score += self.severity_weights.get(severity, 1)
        
        max_score = len(findings) * 10
        analysis['risk_score'] = round((total_score / max_score) * 100) if max_score > 0 else 0
        
        # Prioritize findings
        analysis['prioritized_findings'] = sorted(
            findings,
            key=lambda x: self.severity_weights.get(x.get('severity', 'Low'), 1),
            reverse=True
        )
        
        # Generate summary
        critical_count = len([f for f in findings if f.get('severity') == 'Critical'])
        high_count = len([f for f in findings if f.get('severity') == 'High'])
        
        if critical_count > 0:
            analysis['summary'] = f'CRITICAL: Found {critical_count} critical vulnerabilities that require immediate attention.'
            analysis['estimated_impact'] = 'High probability of successful compromise'
        elif high_count > 0:
            analysis['summary'] = f'HIGH: Found {high_count} high-severity vulnerabilities that should be addressed urgently.'
            analysis['estimated_impact'] = 'Moderate to high risk of exploitation'
        else:
            analysis['summary'] = f'Found {len(findings)} vulnerabilities with medium to low severity.'
            analysis['estimated_impact'] = 'Low to moderate risk'
        
        # Generate remediation plan
        for finding in analysis['prioritized_findings'][:5]:
            analysis['remediation_plan'].append({
                'finding': finding.get('title'),
                'remediation': finding.get('remediation'),
                'priority': 'High' if finding.get('severity') in ['Critical', 'High'] else 'Medium'
            })
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis['risk_score'], critical_count, high_count)
        
        return analysis
    
    def _generate_recommendations(self, risk_score: int, critical: int, high: int) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if risk_score > 70:
            recommendations.append('Immediately patch all critical vulnerabilities')
            recommendations.append('Consider temporary isolation of affected systems')
            recommendations.append('Conduct an emergency security review')
        elif risk_score > 40:
            recommendations.append('Prioritize remediation of high-severity findings within 7 days')
            recommendations.append('Review and update firewall rules')
            recommendations.append('Implement additional monitoring for affected services')
        else:
            recommendations.append('Follow standard patch management cycles')
            recommendations.append('Continue regular security assessments')
            recommendations.append('Maintain current security controls')
        
        recommendations.append('Document all findings and remediation actions')
        recommendations.append('Schedule follow-up assessment after remediation')
        
        return recommendations
