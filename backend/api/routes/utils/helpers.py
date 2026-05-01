"""Helper utilities for API"""

import json
from datetime import datetime
from typing import Dict, List, Any

def format_response(data: Any, success: bool = True, message: str = None) -> Dict:
    """Format API response consistently"""
    response = {
        'success': success,
        'data': data,
        'timestamp': datetime.now().isoformat()
    }
    
    if message:
        response['message'] = message
    
    return response

def paginate_list(items: List, page: int = 1, per_page: int = 20) -> Dict:
    """Paginate a list of items"""
    start = (page - 1) * per_page
    end = start + per_page
    
    return {
        'items': items[start:end],
        'total': len(items),
        'page': page,
        'per_page': per_page,
        'total_pages': (len(items) + per_page - 1) // per_page
    }

def filter_findings_by_severity(findings: List, severity: str) -> List:
    """Filter findings by severity"""
    if severity == 'all':
        return findings
    return [f for f in findings if f.get('severity', '').lower() == severity.lower()]

def aggregate_stats(data: List) -> Dict:
    """Aggregate statistics from data"""
    stats = {
        'total': len(data),
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    for item in data:
        severity = item.get('severity', 'info')
        if severity in stats:
            stats[severity.lower()] += 1
    
    return stats

def generate_summary(findings: List) -> str:
    """Generate summary text from findings"""
    if not findings:
        return "No findings discovered."
    
    stats = aggregate_stats(findings)
    
    if stats['critical'] > 0:
        return f"CRITICAL: {stats['critical']} critical vulnerabilities require immediate attention."
    elif stats['high'] > 0:
        return f"HIGH: {stats['high']} high-severity vulnerabilities need remediation."
    else:
        return f"Found {stats['total']} vulnerabilities with medium to low severity."

def calculate_risk_score(findings: List) -> int:
    """Calculate risk score from findings"""
    if not findings:
        return 0
    
    weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 1}
    total = sum(weights.get(f.get('severity', 'Low'), 1) for f in findings)
    max_score = len(findings) * 10
    
    return round((total / max_score) * 100) if max_score > 0 else 0