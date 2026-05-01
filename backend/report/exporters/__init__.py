"""
Report Templates - HTML templates for different report types
"""

from .executive_template import EXECUTIVE_TEMPLATE
from .technical_template import TECHNICAL_TEMPLATE
from .findings_template import FINDINGS_TEMPLATE

__all__ = [
    'EXECUTIVE_TEMPLATE',
    'TECHNICAL_TEMPLATE',
    'FINDINGS_TEMPLATE'
]