"""Input validators for API endpoints"""

import re
from ipaddress import ip_address, ip_network

def validate_target(target: str) -> bool:
    """Validate target IP or domain"""
    if not target:
        return False
    
    # Check if it's an IP address
    try:
        ip_address(target)
        return True
    except:
        pass
    
    # Check if it's a domain name
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(domain_pattern, target) and len(target) <= 253:
        return True
    
    # Check if it's a CIDR range
    try:
        ip_network(target, strict=False)
        return True
    except:
        pass
    
    return False

def validate_scan_type(scan_type: str) -> bool:
    """Validate scan type"""
    valid_types = ['quick', 'full', 'web', 'network', 'custom']
    return scan_type in valid_types

def validate_report_type(report_type: str) -> bool:
    """Validate report type"""
    valid_types = ['executive', 'technical', 'full', 'summary']
    return report_type in valid_types

def validate_severity(severity: str) -> bool:
    """Validate severity level"""
    valid_levels = ['Critical', 'High', 'Medium', 'Low', 'Info', 'all']
    return severity in valid_levels

def sanitize_command(command: str) -> str:
    """Sanitize command input"""
    dangerous = ['rm -rf', 'dd if=', 'mkfs', ':(){', 'fork bomb', '> /dev/sda']
    for d in dangerous:
        if d in command.lower():
            return ''
    return command