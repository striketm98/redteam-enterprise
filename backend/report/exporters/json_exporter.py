"""
JSON Exporter - Export reports as JSON
"""

import json
from datetime import datetime
from typing import Dict


class JSONExporter:
    """Export security reports as JSON"""
    
    def export(self, report_data: Dict, filepath: str) -> str:
        """Export report to JSON"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return filepath