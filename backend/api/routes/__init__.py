"""Route modules for RedTeamKa API"""

from .auth import auth_bp
from .scan import scan_bp
from .exploit import exploit_bp
from .report import report_bp
from .findings import findings_bp
from .dashboard import dashboard_bp
from .admin import admin_bp

__all__ = [
    'auth_bp',
    'scan_bp', 
    'exploit_bp',
    'report_bp',
    'findings_bp',
    'dashboard_bp',
    'admin_bp'
]