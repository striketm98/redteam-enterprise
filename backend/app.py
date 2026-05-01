from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import json
import uuid
import subprocess
import threading
from functools import wraps

# Import custom modules
from core.scan_engine import ScanEngine
from core.exploit_engine import ExploitEngine
from core.report_engine import ReportEngine
from core.ai_analyzer import AIAnalyzer

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'redteamka-secret-key-2024')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize engines
scan_engine = ScanEngine()
exploit_engine = ExploitEngine()
report_engine = ReportEngine()
ai_analyzer = AIAnalyzer()

# ============================================
# USER DATABASE (In-memory with persistence)
# ============================================

class User(UserMixin):
    def __init__(self, id, username, password_hash, role, email):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role  # 'pentest' or 'client'
        self.email = email

users = {}
scans = {}
findings = []
reports = []
sessions_data = {}

# Default users
default_users = {
    'pentest': {
        'password': 'RedTeamKa@2024',
        'role': 'pentest',
        'email': 'pentest@redteamka.local'
    },
    'client': {
        'password': 'Client@2024',
        'role': 'client',
        'email': 'client@redteamka.local'
    }
}

def init_users():
    for username, data in default_users.items():
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
# AUTHENTICATION ROUTES
# ============================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = users.get(username)
    
    if user and check_password_hash(user.password_hash, password):
        login_user(user, remember=True)
        session.permanent = True
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'email': user.email
            },
            'token': session.sid,
            'message': f'Welcome back, {username}!'
        })
    
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'role': current_user.role,
        'email': current_user.email
    })

# ============================================
# SCANNING ROUTES
# ============================================

@app.route('/api/scan/start', methods=['POST'])
@login_required
def start_scan():
    if current_user.role != 'pentest':
        return jsonify({'error': 'Only pentesters can start scans'}), 403
    
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'full')  # full, quick, custom
    options = data.get('options', {})
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Start scan in background thread
    def run_scan():
        try:
            update_status('running', f'Starting {scan_type} scan on {target}')
            
            # Run comprehensive scan based on type
            if scan_type == 'quick':
                results = scan_engine.quick_scan(target)
            elif scan_type == 'full':
                results = scan_engine.full_scan(target)
            elif scan_type == 'web':
                results = scan_engine.web_scan(target)
            elif scan_type == 'network':
                results = scan_engine.network_scan(target)
            else:
                results = scan_engine.custom_scan(target, options)
            
            # AI Analysis
            update_status('analyzing', 'AI analyzing scan results...')
            ai_analysis = ai_analyzer.analyze_results(results)
            
            # Generate findings
            findings_list = scan_engine.generate_findings(results)
            
            # Store results
            scans[scan_id] = {
                'id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'status': 'completed',
                'results': results,
                'findings': findings_list,
                'ai_analysis': ai_analysis,
                'created_by': current_user.username,
                'created_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            }
            
            # Add to global findings
            for finding in findings_list:
                finding['scan_id'] = scan_id
                finding['scan_target'] = target
                findings.append(finding)
            
            # Emit completion event
            socketio.emit('scan_completed', {
                'scan_id': scan_id,
                'findings_count': len(findings_list),
                'message': f'Scan completed on {target}'
            })
            
            update_status('completed', f'Scan completed. Found {len(findings_list)} findings.')
            
        except Exception as e:
            scans[scan_id] = {
                'id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'status': 'failed',
                'error': str(e),
                'created_by': current_user.username,
                'created_at': datetime.now().isoformat()
            }
            socketio.emit('scan_failed', {'scan_id': scan_id, 'error': str(e)})
            update_status('failed', f'Scan failed: {str(e)}')
    
    def update_status(status, message):
        socketio.emit('scan_status', {
            'scan_id': scan_id,
            'status': status,
            'message': message
        })
    
    # Start background thread
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
@login_required
def get_scan_status(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'status': scan.get('status'),
        'progress': scan.get('progress', 0),
        'message': scan.get('message', 'Processing...')
    })

@app.route('/api/scan/results/<scan_id>', methods=['GET'])
@login_required
def get_scan_results(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Check permission
    if scan['created_by'] != current_user.username and current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    return jsonify(scan)

@app.route('/api/scans', methods=['GET'])
@login_required
def get_all_scans():
    if current_user.role == 'pentest':
        user_scans = list(scans.values())
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
    
    # Return simplified list
    return jsonify([{
        'id': s['id'],
        'target': s['target'],
        'scan_type': s['scan_type'],
        'status': s['status'],
        'findings_count': len(s.get('findings', [])),
        'created_at': s['created_at'],
        'completed_at': s.get('completed_at')
    } for s in user_scans])

# ============================================
# EXPLOIT ROUTES
# ============================================

@app.route('/api/exploit/run', methods=['POST'])
@login_required
def run_exploit():
    if current_user.role != 'pentest':
        return jsonify({'error': 'Only pentesters can run exploits'}), 403
    
    data = request.json
    exploit_name = data.get('exploit')
    target = data.get('target')
    options = data.get('options', {})
    
    try:
        result = exploit_engine.run_exploit(exploit_name, target, options)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/exploits/list', methods=['GET'])
@login_required
def list_exploits():
    exploits = exploit_engine.list_available_exploits()
    return jsonify(exploits)

# ============================================
# REPORT ROUTES
# ============================================

@app.route('/api/report/generate', methods=['POST'])
@login_required
def generate_report():
    data = request.json
    scan_ids = data.get('scan_ids', [])
    report_type = data.get('type', 'executive')  # executive, technical, full
    
    # Gather scan data
    report_scans = []
    for scan_id in scan_ids:
        scan = scans.get(scan_id)
        if scan and (scan['created_by'] == current_user.username or current_user.role == 'pentest'):
            report_scans.append(scan)
    
    if not report_scans:
        return jsonify({'error': 'No valid scans found'}), 404
    
    # Generate report
    report_data = report_engine.generate_report(report_scans, report_type, current_user.username)
    
    # Save report
    report_id = str(uuid.uuid4())
    report = {
        'id': report_id,
        'title': f"Security Assessment - {report_type.upper()} Report",
        'type': report_type,
        'scans': [s['id'] for s in report_scans],
        'data': report_data,
        'generated_by': current_user.username,
        'generated_at': datetime.now().isoformat()
    }
    reports.append(report)
    
    return jsonify({
        'success': True,
        'report_id': report_id,
        'report': report_data
    })

@app.route('/api/report/download/<report_id>', methods=['GET'])
@login_required
def download_report(report_id):
    report = next((r for r in reports if r['id'] == report_id), None)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    # Generate PDF
    pdf_path = report_engine.generate_pdf(report)
    
    return send_from_directory(
        os.path.dirname(pdf_path),
        os.path.basename(pdf_path),
        as_attachment=True
    )

@app.route('/api/reports', methods=['GET'])
@login_required
def get_reports():
    if current_user.role == 'pentest':
        user_reports = reports
    else:
        user_reports = [r for r in reports if r['generated_by'] == current_user.username]
    
    return jsonify(user_reports)

# ============================================
# FINDINGS ROUTES
# ============================================

@app.route('/api/findings', methods=['GET'])
@login_required
def get_findings():
    if current_user.role == 'pentest':
        user_findings = findings
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
        user_scan_ids = [s['id'] for s in user_scans]
        user_findings = [f for f in findings if f['scan_id'] in user_scan_ids]
    
    return jsonify(user_findings)

@app.route('/api/findings/by-severity', methods=['GET'])
@login_required
def get_findings_by_severity():
    severity = request.args.get('severity', 'all')
    
    if current_user.role == 'pentest':
        user_findings = findings
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
        user_scan_ids = [s['id'] for s in user_scans]
        user_findings = [f for f in findings if f['scan_id'] in user_scan_ids]
    
    if severity != 'all':
        user_findings = [f for f in user_findings if f.get('severity', '').lower() == severity.lower()]
    
    return jsonify(user_findings)

# ============================================
# DASHBOARD STATS
# ============================================

@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    if current_user.role == 'pentest':
        total_scans = len(scans)
        completed_scans = len([s for s in scans.values() if s['status'] == 'completed'])
        critical_findings = len([f for f in findings if f.get('severity') == 'Critical'])
        high_findings = len([f for f in findings if f.get('severity') == 'High'])
        medium_findings = len([f for f in findings if f.get('severity') == 'Medium'])
        low_findings = len([f for f in findings if f.get('severity') == 'Low'])
        total_findings = len(findings)
        unique_targets = len(set([s['target'] for s in scans.values()]))
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
        user_scan_ids = [s['id'] for s in user_scans]
        user_findings = [f for f in findings if f['scan_id'] in user_scan_ids]
        
        total_scans = len(user_scans)
        completed_scans = len([s for s in user_scans if s['status'] == 'completed'])
        critical_findings = len([f for f in user_findings if f.get('severity') == 'Critical'])
        high_findings = len([f for f in user_findings if f.get('severity') == 'High'])
        medium_findings = len([f for f in user_findings if f.get('severity') == 'Medium'])
        low_findings = len([f for f in user_findings if f.get('severity') == 'Low'])
        total_findings = len(user_findings)
        unique_targets = len(set([s['target'] for s in user_scans]))
    
    return jsonify({
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'critical_findings': critical_findings,
        'high_findings': high_findings,
        'medium_findings': medium_findings,
        'low_findings': low_findings,
        'total_findings': total_findings,
        'unique_targets': unique_targets,
        'user_role': current_user.role,
        'user_name': current_user.username
    })

@app.route('/api/dashboard/recent', methods=['GET'])
@login_required
def get_recent_activity():
    if current_user.role == 'pentest':
        recent_scans = sorted(scans.values(), key=lambda x: x.get('created_at', ''), reverse=True)[:10]
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
        recent_scans = sorted(user_scans, key=lambda x: x.get('created_at', ''), reverse=True)[:10]
    
    return jsonify([{
        'id': s['id'],
        'target': s['target'],
        'scan_type': s['scan_type'],
        'status': s['status'],
        'created_at': s['created_at'],
        'findings_count': len(s.get('findings', []))
    } for s in recent_scans])

# ============================================
# TOOLS CONFIGURATION
# ============================================

@app.route('/api/tools', methods=['GET'])
@login_required
def get_available_tools():
    tools = [
        {'name': 'Nmap', 'description': 'Network discovery and security scanning', 'category': 'network'},
        {'name': 'Metasploit', 'description': 'Exploitation framework', 'category': 'exploit'},
        {'name': 'Hydra', 'description': 'Password brute-forcing tool', 'category': 'auth'},
        {'name': 'SQLmap', 'description': 'SQL injection detection and exploitation', 'category': 'web'},
        {'name': 'Gobuster', 'description': 'Directory and DNS brute-forcing', 'category': 'web'},
        {'name': 'Nikto', 'description': 'Web server scanner', 'category': 'web'},
        {'name': 'Burp Suite', 'description': 'Web vulnerability scanner', 'category': 'web'},
        {'name': 'Wireshark', 'description': 'Network protocol analyzer', 'category': 'network'}
    ]
    return jsonify(tools)

# ============================================
# HEALTH CHECK
# ============================================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'name': 'RedTeamKa',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat(),
        'users': len(users),
        'scans': len(scans),
        'findings': len(findings)
    })

# ============================================
# FRONTEND ROUTES
# ============================================

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(app.static_folder, path)

# ============================================
# WEB SOCKET EVENTS
# ============================================

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')
    emit('connected', {'message': 'Connected to RedTeamKa'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')

# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    init_users()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║                    🔴 REDTEAMKA - Complete Platform 🔴            ║
    ║                                                                   ║
    ║              Enterprise Red Team Automation Framework             ║
    ║                                                                   ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║                                                                   ║
    ║  🌐 Web Interface: http://localhost:8888                         ║
    ║  📡 API Endpoint: http://localhost:8888/api                      ║
    ║                                                                   ║
    ║  🔐 Default Credentials:                                         ║
    ║     🔴 Pentester:  pentest / RedTeamKa@2024                      ║
    ║     🔵 Client:     client / Client@2024                          ║
    ║                                                                   ║
    ║  🛠️  Integrated Tools:                                           ║
    ║     • Nmap - Network scanning                                    ║
    ║     • Metasploit - Exploitation                                  ║
    ║     • Hydra - Password attacks                                   ║
    ║     • SQLmap - SQL injection                                     ║
    ║     • Gobuster - Directory brute-force                           ║
    ║     • Nikto - Web vulnerability scanning                         ║
    ║                                                                   ║
    ║  🤖 AI Features:                                                 ║
    ║     • Automated finding analysis                                 ║
    ║     • Smart remediation suggestions                              ║
    ║     • Risk scoring and prioritization                            ║
    ║                                                                   ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║  ⚠️  EDUCATIONAL PURPOSE ONLY - Use responsibly                 ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
