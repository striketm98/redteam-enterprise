"""
RedTeamKa Core Modules
Enterprise Red Team Automation Framework
"""

# Core engines
from .scan_engine import ScanEngine
from .exploit_engine import ExploitEngine
from .report_engine import ReportEngine
from .ai_analyzer import AIAnalyzer
from .auth_manager import AuthManager

# Legacy/Additional modules (kept for compatibility)
from .decision_engine import DecisionEngine
from .cred_engine import CredentialEngine
from .privesc_engine import PrivEscEngine
from .exploit_matcher import ExploitMatcher
from .task_runner import TaskRunner

__all__ = [
    # New core engines
    'ScanEngine',
    'ExploitEngine', 
    'ReportEngine',
    'AIAnalyzer',
    'AuthManager',
    
    # Legacy modules
    'DecisionEngine',
    'CredentialEngine',
    'PrivEscEngine',
    'ExploitMatcher',
    'TaskRunner'
]

__version__ = '2.0.0'
__author__ = 'RedTeamKa Team'
__description__ = 'Enterprise Red Team Automation Framework'