"""
CSV Exporter - Export findings as CSV
"""

import csv
from typing import List, Dict


class CSVExporter:
    """Export findings as CSV"""
    
    def export(self, findings: List[Dict], filepath: str) -> str:
        """Export findings to CSV"""
        if not findings:
            return filepath
        
        # Get all unique keys from findings
        fieldnames = set()
        for finding in findings:
            fieldnames.update(finding.keys())
        
        fieldnames = sorted(list(fieldnames))
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings)
        
        return filepath