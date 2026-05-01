from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import os
import json
from datetime import datetime
from core.auth import db, User, Scan, Finding, init_db
from core.scan_engine import ScanEngine
from core.report_generator import ReportGenerator

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'redteam-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///redteam.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Initialize components
scan_engine = ScanEngine()
report_generator = ReportGenerator()

# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        login_user(user)
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'user': user.to_dict(),
            'message': f'Welcome {user.username} ({user.role})'
        })
    
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out'})

@app.route('/api/current-user')
@login_required
def current_user_info():
    return jsonify(current_user.to_dict())

# ============================================
# SCAN ROUTES (Pentest only)
# ============================================

@app.route('/api/scan', methods=['POST'])
@login_required
def start_scan():
    """Start a new security scan (Pentest only)"""
    if not current_user.has_permission('scan'):
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'full')
    
    # Create scan record
    scan = Scan(
        target=target,
        scan_type=scan_type,
        status='running',
        created_by=current_user.id
    )
    db.session.add(scan)
    db.session.commit()
    
    # Run scan asynchronously (simplified - in production use Celery)
    try:
        if scan_type == 'nmap':
            results = scan_engine.run_nmap_scan(target, 'full')
        elif scan_type == 'quick':
            results = scan_engine.run_nmap_scan(target, 'quick')
        elif scan_type == 'web':
            results = scan_engine.run_gobuster_scan(target)
        else:
            results = scan_engine.run_full_assessment(target)
        
        scan.results = json.dumps(results)
        scan.status = 'completed'
        
        # Add findings to database
        findings = results.get('all_findings', results.get('findings', []))
        for finding_data in findings:
            finding = Finding(
                title=finding_data.get('title'),
                severity=finding_data.get('severity'),
                description=finding_data.get('description'),
                remediation=finding_data.get('remediation'),
                scan_id=scan.id
            )
            db.session.add(finding)
        
        scan.findings_count = len(findings)
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        
    except Exception as e:
        scan.status = 'failed'
        scan.results = json.dumps({'error': str(e)})
        db.session.commit()
        return jsonify({'error': str(e)}), 500
    
    return jsonify({'scan_id': scan.id, 'status': 'completed'})

@app.route('/api/scans')
@login_required
def get_scans():
    """Get scans (filtered by role)"""
    if current_user.role == 'pentest':
        scans = Scan.query.order_by(Scan.created_at.desc()).all()
    else:
        scans = Scan.query.filter_by(created_by=current_user.id).order_by(Scan.created_at.desc()).all()
    
    return jsonify([scan.to_dict() for scan in scans])

@app.route('/api/scans/<scan_id>')
@login_required
def get_scan(scan_id):
    """Get specific scan details"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check permission
    if scan.created_by != current_user.id and current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    results = json.loads(scan.results) if scan.results else {}
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    
    return jsonify({
        'scan': scan.to_dict(),
        'results': results,
        'findings': [f.to_dict() for f in findings]
    })

# ============================================
# REPORT ROUTES
# ============================================

@app.route('/api/reports/<scan_id>', methods=['GET'])
@login_required
def generate_report(scan_id):
    """Generate PDF report for a scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check permission
    if scan.created_by != current_user.id and current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    results = json.loads(scan.results) if scan.results else {}
    
    # Generate report
    report_path = report_generator.generate_pdf_report(scan, findings, results)
    
    return send_from_directory(
        directory=os.path.dirname(report_path),
        path=os.path.basename(report_path),
        as_attachment=True
    )

@app.route('/api/findings')
@login_required
def get_findings():
    """Get all findings (filtered by role)"""
    if current_user.role == 'pentest':
        findings = Finding.query.all()
    else:
        findings = Finding.query.join(Scan).filter(Scan.created_by == current_user.id).all()
    
    return jsonify([f.to_dict() for f in findings])

# ============================================
# ADMIN ROUTES (Pentest only)
# ============================================

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Get all users (admin only)"""
    if not current_user.has_permission('manage_users'):
        return jsonify({'error': 'Permission denied'}), 403
    
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    """Create new user (admin only)"""
    if not current_user.has_permission('manage_users'):
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.json
    user = User(
        username=data['username'],
        email=data['email'],
        role=data.get('role', 'client')
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify(user.to_dict()), 201

# ============================================
# DASHBOARD STATS
# ============================================

@app.route('/api/stats')
@login_required
def get_stats():
    """Get dashboard statistics"""
    if current_user.role == 'pentest':
        total_scans = Scan.query.count()
        critical_findings = Finding.query.filter_by(severity='Critical').count()
        high_findings = Finding.query.filter_by(severity='High').count()
        total_findings = Finding.query.count()
    else:
        total_scans = Scan.query.filter_by(created_by=current_user.id).count()
        critical_findings = Finding.query.join(Scan).filter(
            Scan.created_by == current_user.id,
            Finding.severity == 'Critical'
        ).count()
        high_findings = Finding.query.join(Scan).filter(
            Scan.created_by == current_user.id,
            Finding.severity == 'High'
        ).count()
        total_findings = Finding.query.join(Scan).filter(
            Scan.created_by == current_user.id
        ).count()
    
    return jsonify({
        'total_scans': total_scans,
        'critical_findings': critical_findings,
        'high_findings': high_findings,
        'total_findings': total_findings,
        'user_role': current_user.role
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
# INITIALIZATION
# ============================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_db()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     RED TEAM ENTERPRISE FRAMEWORK - DUAL ROLE EDITION         ║
    ║                                                               ║
    ║  Access: http://localhost:8087                               ║
    ║                                                               ║
    ║  Default Credentials:                                        ║
    ║    Pentester: pentest / Pentest@123                         ║
    ║    Client:    client / Client@123                           ║
    ║                                                               ║
    ║  Roles:                                                      ║
    ║    🔴 Pentester: Full access to scanning, reporting, admin   ║
    ║    🔵 Client:    View-only access to reports                ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    socketio.run(app, host='0.0.0.0', port=8087, debug=False)
