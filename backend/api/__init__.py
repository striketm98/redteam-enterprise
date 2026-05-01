"""API module for RedTeamKa"""

from flask import Blueprint
from flask_cors import CORS

# Create main API blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Import route modules
from .routes.auth import auth_bp
from .routes.scan import scan_bp
from .routes.exploit import exploit_bp
from .routes.report import report_bp
from .routes.findings import findings_bp
from .routes.dashboard import dashboard_bp
from .routes.admin import admin_bp

# Register blueprints
api_bp.register_blueprint(auth_bp)
api_bp.register_blueprint(scan_bp)
api_bp.register_blueprint(exploit_bp)
api_bp.register_blueprint(report_bp)
api_bp.register_blueprint(findings_bp)
api_bp.register_blueprint(dashboard_bp)
api_bp.register_blueprint(admin_bp)

def init_api(app):
    """Initialize API with app"""
    CORS(app, supports_credentials=True)
    app.register_blueprint(api_bp)
