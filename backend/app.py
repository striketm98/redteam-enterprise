"""
RedTeamKa - Enterprise Red Team Automation Platform
Complete Integration of all modules
"""

from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import json
import uuid
import threading
import logging

# ============================================
# IMPORTS FROM MODULAR COMPONENTS
# ============================================

# Core modules
from core.scan_engine import ScanEngine
from core.exploit_engine import ExploitEngine
from core.report_engine import ReportEngine
from core.ai_analyzer import AIAnalyzer
from core.decision_engine import DecisionEngine
from core.cred_engine import CredentialEngine
from core.privesc_engine import PrivEscEngine
from core.exploit_matcher import ExploitMatcher
from core.task_runner import TaskRunner

# Graph modules
from graph.neo4j_client import Neo4jClient
from graph.attack_graph import AttackGraph
from graph.path_analyzer import PathAnalyzer

# Lab modules
from lab.deployer import LabDeployer
from lab.docker_manager import DockerManager
from lab.orchestrator import LabOrchestrator

# Report modules
from report.generator import ReportGenerator
from report.exporters.pdf_exporter import PDFExporter
from report.exporters.html_exporter import HTMLExporter

# API modules
from api import init_api
from api.routes.auth import init_users
from api.routes.scans import init_scan_engine
from api.routes.exploits import init_exploit_engine
from api.routes.reports import init_report_engine
from api.routes.findings import init_findings
from api.routes.dashboard import init_dashboard
from api.routes.admin import init_admin
from api.routes.labs import init_lab_deployer
from api.routes.tools import init_tools

# Session modules
from sessions.session_manager import SessionManager
from sessions.session_store import SessionStore
from sessions.session_cleanup import SessionCleanup

# ============================================
# FLASK APP INITIALIZATION
# ============================================

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'redteamka-super-secret-key-2024')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True

CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

# ============================================
# USER MODEL
# ============================================

class User(UserMixin):
    def __init__(self, id, username, password_hash, role, email):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.email = email

# Global storage
users = {}
scans = {}
findings = []
reports = []

# Default users
DEFAULT_USERS = {
    'pentest': {
        'password': 'RedTeamKa@2024',
        'role': 'pentest',
        'email': 'pentest@redteamka.local',
        'name': 'Pentester'
    },
    'client': {
        'password': 'Client@2024',
        'role': 'client',
        'email': 'client@redteamka.local',
        'name': 'Client User'
    }
}

def init_users_db():
    """Initialize default users"""
    for username, data in DEFAULT_USERS.items():
        if username not in users:
            user_id = str(uuid.uuid4())
            users[username] = User(
                id=user_id,
                username=username,
                password_hash=generate_password_hash(data['password']),
                role=data['role'],
                email=data['email']
            )
            print(f"✅ Created user: {username} ({data['role']})")

@login_manager.user_loader
def load_user(user_id):
    for user in users.values():
        if user.id == user_id:
            return user
    return None

# ============================================
# INITIALIZE ALL ENGINES
# ============================================

# Core engines
scan_engine = ScanEngine()
exploit_engine = ExploitEngine()
report_engine = ReportEngine()
ai_analyzer = AIAnalyzer()
decision_engine = DecisionEngine()
cred_engine = CredentialEngine()
privesc_engine = PrivEscEngine()
exploit_matcher = ExploitMatcher()
task_runner = TaskRunner()

# Graph engines
neo4j_client = Neo4jClient()
attack_graph = AttackGraph(neo4j_client)
path_analyzer = PathAnalyzer(attack_graph)

# Lab engines
lab_deployer = LabDeployer()
docker_manager = DockerManager()
lab_orchestrator = LabOrchestrator()

# Session management
session_manager = SessionManager()
session_store = SessionStore()
session_cleanup = SessionCleanup(session_manager, session_store)

# Start cleanup service
session_cleanup.start()

# ============================================
# INITIALIZE API WITH ALL DEPENDENCIES
# ============================================

# Initialize API components
init_users(users)
init_scan_engine(scan_engine, scans)
init_exploit_engine(exploit_engine)
init_report_engine(report_engine, scans)
init_findings(findings, scans)
init_dashboard(scans, findings, users)
init_admin(users, scans, findings)
init_lab_deployer(lab_deployer)
init_tools()

# Initialize API
from api import api_bp
app.register_blueprint(api_bp, url_prefix='/api')

# ============================================
# FRONTEND ROUTES
# ============================================

@app.route('/')
def serve_frontend():
    """Serve the main frontend page"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory(app.static_folder, path)

# ============================================
# DIRECT API ENDPOINTS (Fallback)
# ============================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'name': 'RedTeamKa',
        'version': '3.0.0',
        'timestamp': datetime.now().isoformat(),
        'modules': {
            'core': 'loaded',
            'graph': neo4j_client.use_neo4j if hasattr(neo4j_client, 'use_neo4j') else 'memory',
            'lab': 'ready',
            'reports': 'ready',
            'sessions': session_manager.get_active_sessions_count()
        },
        'statistics': {
            'users': len(users),
            'scans': len(scans),
            'findings': len(findings),
            'reports': len(reports),
            'active_sessions': session_manager.get_active_sessions_count()
        }
    })

@app.route('/api/info', methods=['GET'])
def system_info():
    """System information endpoint"""
    return jsonify({
        'name': 'RedTeamKa Enterprise Platform',
        'version': '3.0.0',
        'description': 'Enterprise Red Team Automation Framework',
        'features': [
            'Multi-tool scanning (Nmap, Gobuster, Nikto, Hydra, SQLmap)',
            'AI-powered vulnerability analysis',
            'Professional report generation (PDF, HTML, JSON, CSV)',
            'Lab environment orchestration',
            'Attack graph visualization',
            'Role-based access control (Pentest/Client)',
            'Real-time WebSocket updates',
            'Session management with persistence'
        ],
        'integrations': [
            'Metasploit Framework',
            'Nmap Security Scanner',
            'Gobuster Directory Brute-forcer',
            'Nikto Web Scanner',
            'Hydra Password Brute-forcer',
            'SQLmap SQL Injection Tool'
        ]
    })

# ============================================
# DIRECT SESSION ENDPOINTS
# ============================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate user and create session"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = users.get(username)
    
    if user and check_password_hash(user.password_hash, password):
        login_user(user, remember=True)
        session.permanent = True
        
        # Create application session
        session_token = session_manager.create_session(user.id, {
            'username': user.username,
            'role': user.role,
            'email': user.email
        })
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'email': user.email
            },
            'token': session_token,
            'message': f'Welcome back, {username}!'
        })
    
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    """Logout user and destroy session"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    session_manager.delete_session(token)
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current authenticated user"""
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'role': current_user.role,
        'email': current_user.email
    })

# ============================================
# WEBSOCKET EVENTS
# ============================================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print(f'✅ Client connected: {request.sid}')
    emit('connected', {
        'message': 'Connected to RedTeamKa',
        'timestamp': datetime.now().isoformat()
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print(f'❌ Client disconnected: {request.sid}')

@socketio.on('ping')
def handle_ping():
    """Handle ping for keep-alive"""
    emit('pong', {'timestamp': datetime.now().isoformat()})

# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Endpoint not found',
        'path': request.path,
        'method': request.method
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'error': 'Internal server error',
        'message': str(error)
    }), 500

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors"""
    return jsonify({
        'error': 'Forbidden',
        'message': 'You do not have permission to access this resource'
    }), 403

@app.errorhandler(401)
def unauthorized(error):
    """Handle 401 errors"""
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication required'
    }), 401

# ============================================
# SHUTDOWN HANDLER
# ============================================

def shutdown_session_cleanup():
    """Cleanup on application shutdown"""
    print("🛑 Shutting down session cleanup service...")
    session_cleanup.stop()
    if hasattr(session_store, 'close'):
        session_store.close()
    print("✅ Cleanup complete")

import atexit
atexit.register(shutdown_session_cleanup)

# ============================================
# MAIN ENTRY POINT
# ============================================

if __name__ == '__main__':
    # Initialize database
    init_users_db()
    
    # Print startup banner
    print("""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                               ║
    ║                    🔴🔥 REDTEAMKA - ENTERPRISE PLATFORM 🔥🔴                    ║
    ║                                                                               ║
    ║                    Complete Red Team Automation Framework                     ║
    ║                                   v3.0.0                                      ║
    ║                                                                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                                                                               ║
    ║  🌐 Web Interface:  http://localhost:8888                                     ║
    ║  📡 API Endpoint:   http://localhost:8888/api                                 ║
    ║  💚 Health Check:   http://localhost:8888/api/health                          ║
    ║                                                                               ║
    ║  🔐 Default Credentials:                                                      ║
    ║     🔴 Pentester:  pentest / RedTeamKa@2024                                   ║
    ║     🔵 Client:     client / Client@2024                                       ║
    ║                                                                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                                                                               ║
    ║  🛠️  INTEGRATED TOOLS:                                                        ║
    ║     • Nmap          - Network discovery and port scanning                     ║
    ║     • Metasploit    - Exploitation framework                                  ║
    ║     • Hydra         - Password brute-forcing                                  ║
    ║     • SQLmap        - SQL injection detection                                 ║
    ║     • Gobuster      - Directory and DNS brute-forcing                         ║
    ║     • Nikto         - Web vulnerability scanner                               ║
    ║                                                                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                                                                               ║
    ║  🧠 AI FEATURES:                                                              ║
    ║     • Automated vulnerability analysis                                        ║
    ║     • Smart remediation suggestions                                           ║
    ║     • Risk scoring and prioritization                                         ║
    ║     • Attack path prediction                                                  ║
    ║                                                                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                                                                               ║
    ║  📊 MODULE STATUS:                                                            ║
    ║     ✅ Core Engine    - Loaded                                                ║
    ║     ✅ Graph Engine   - {'Neo4j Connected' if neo4j_client.use_neo4j else 'In-Memory Mode'}        
    ║     ✅ Lab Engine     - Ready                                                 ║
    ║     ✅ Report Engine  - Ready                                                 ║
    ║     ✅ Session Manager - Running                                              ║
    ║                                                                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  ⚠️  EDUCATIONAL PURPOSE ONLY - Use responsibly in authorized environments   ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Start the application
    socketio.run(
        app,
        host='0.0.0.0',
        port=8888,
        debug=False,
        allow_unsafe_werkzeug=True
    )