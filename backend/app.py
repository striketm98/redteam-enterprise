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
import re
from functools import wraps

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

# ============================================
# CORE ENGINE CLASSES (Built-in to avoid imports)
# ============================================

class ScanEngine:
    """Built-in Scan Engine"""
    
    def quick_scan(self, target):
        results = {
            'target': target,
            'scan_type': 'quick',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'open_ports': []
        }
        try:
            cmd = f"nmap -F -sV --min-rate 1000 {target} 2>/dev/null"
            output = self._run_command(cmd)
            results['open_ports'] = self._parse_ports(output)
            results['findings'] = self._generate_findings_from_ports(results['open_ports'])
            results['status'] = 'completed'
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = str(e)
        return results
    
    def full_scan(self, target):
        results = {
            'target': target,
            'scan_type': 'full',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'open_ports': []
        }
        try:
            cmd = f"nmap -p- -sV -sC -O --min-rate 500 {target} 2>/dev/null"
            output = self._run_command(cmd)
            results['open_ports'] = self._parse_ports(output)
            results['findings'] = self._generate_findings_from_ports(results['open_ports'])
            
            # Additional vulnerability checks
            vuln_cmd = f"nmap --script vuln {target} 2>/dev/null"
            vuln_output = self._run_command(vuln_cmd)
            if 'VULNERABLE' in vuln_output:
                results['findings'].append({
                    'title': 'Potential Vulnerabilities Detected',
                    'severity': 'High',
                    'description': 'Nmap vulnerability script detected potential vulnerabilities',
                    'remediation': 'Run detailed vulnerability assessment and apply patches',
                    'cvss_score': 7.5
                })
            results['status'] = 'completed'
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = str(e)
        return results
    
    def web_scan(self, target):
        results = {
            'target': target,
            'scan_type': 'web',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'directories': []
        }
        try:
            url = target if target.startswith(('http://', 'https://')) else f"http://{target}"
            
            # Gobuster directory scan
            cmd = f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -t 30 -q 2>/dev/null"
            output = self._run_command(cmd)
            results['directories'] = self._parse_directories(output)
            
            # Check for sensitive directories
            sensitive = ['admin', 'login', 'backup', 'config', '.git', 'wp-admin']
            for dir in results['directories']:
                for sens in sensitive:
                    if sens in dir.lower():
                        results['findings'].append({
                            'title': f'Sensitive Directory Found: {sens}',
                            'severity': 'Medium',
                            'description': f'Found potentially sensitive directory: {dir}',
                            'remediation': 'Restrict access to admin areas',
                            'cvss_score': 6.5
                        })
                        break
            results['status'] = 'completed'
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = str(e)
        return results
    
    def network_scan(self, target):
        results = {
            'target': target,
            'scan_type': 'network',
            'timestamp': datetime.now().isoformat(),
            'live_hosts': [],
            'findings': []
        }
        try:
            cmd = f"nmap -sn {target} 2>/dev/null"
            output = self._run_command(cmd)
            results['live_hosts'] = self._parse_hosts(output)
            
            if len(results['live_hosts']) > 20:
                results['findings'].append({
                    'title': 'Large Network Exposure',
                    'severity': 'Medium',
                    'description': f'Found {len(results["live_hosts"])} live hosts',
                    'remediation': 'Segment network and implement firewall rules',
                    'cvss_score': 5.0
                })
            results['status'] = 'completed'
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = str(e)
        return results
    
    def custom_scan(self, target, options):
        flags = options.get('flags', '-sV')
        results = {
            'target': target,
            'scan_type': 'custom',
            'command': f"nmap {flags} {target}",
            'timestamp': datetime.now().isoformat(),
            'output': '',
            'findings': []
        }
        try:
            results['output'] = self._run_command(results['command'])
            results['status'] = 'completed'
        except Exception as e:
            results['status'] = 'failed'
            results['error'] = str(e)
        return results
    
    def generate_findings(self, results):
        return results.get('findings', [])
    
    def _run_command(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _parse_ports(self, output):
        ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                match = re.search(r'(\d+)/tcp', line)
                if match:
                    ports.append(int(match.group(1)))
        return ports
    
    def _parse_hosts(self, output):
        hosts = []
        for line in output.split('\n'):
            if 'Nmap scan report for' in line:
                match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if match:
                    hosts.append(match.group())
        return hosts
    
    def _parse_directories(self, output):
        dirs = []
        for line in output.split('\n'):
            if 'Status:' in line:
                dirs.append(line.strip())
        return dirs
    
    def _generate_findings_from_ports(self, ports):
        findings = []
        critical_ports = {21: 'FTP', 23: 'Telnet', 445: 'SMB', 3389: 'RDP', 5900: 'VNC'}
        high_ports = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL'}
        
        for port in ports:
            if port in critical_ports:
                findings.append({
                    'title': f'CRITICAL: {critical_ports[port]} Service Exposed',
                    'severity': 'Critical',
                    'description': f'Port {port} is open - {critical_ports[port]} service accessible',
                    'remediation': f'Restrict access to port {port} using firewall rules',
                    'cvss_score': 9.0
                })
            elif port in high_ports:
                findings.append({
                    'title': f'HIGH: {high_ports[port]} Service Accessible',
                    'severity': 'High',
                    'description': f'Port {port} is open - {high_ports[port]} service available',
                    'remediation': f'Review security configuration for {high_ports[port]}',
                    'cvss_score': 7.5
                })
        return findings


class ExploitEngine:
    """Built-in Exploit Engine"""
    
    def run_exploit(self, exploit_name, target, options):
        return {
            'exploit': exploit_name,
            'target': target,
            'success': True,
            'output': f'Exploit {exploit_name} simulation completed on {target}',
            'note': 'In production, integrate with Metasploit RPC'
        }
    
    def list_available_exploits(self):
        return [
            {'name': 'eternalblue', 'description': 'MS17-010 - Windows SMB RCE', 'risk': 'Critical'},
            {'name': 'ms17_010', 'description': 'EternalBlue variant', 'risk': 'Critical'},
            {'name': 'shellshock', 'description': 'Bash RCE vulnerability', 'risk': 'High'},
            {'name': 'heartbleed', 'description': 'OpenSSL info disclosure', 'risk': 'High'}
        ]


class ReportEngine:
    """Built-in Report Engine"""
    
    def generate_report(self, scans, report_type, username):
        report = {
            'title': f'Security Assessment Report - {report_type.upper()}',
            'generated_by': username,
            'generated_at': datetime.now().isoformat(),
            'report_type': report_type,
            'summary': self._generate_summary(scans),
            'findings': self._aggregate_findings(scans),
            'statistics': self._calculate_stats(scans)
        }
        return report
    
    def generate_pdf(self, report):
        import os
        reports_dir = '/app/reports'
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, f'report_{report["id"]}.html')
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><title>{report.get('title', 'Security Report')}</title>
        <style>
            body {{ font-family: Arial; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 900px; margin: auto; background: white; padding: 30px; }}
            h1 {{ color: #ff3366; }}
            .finding {{ margin: 15px 0; padding: 15px; border-left: 4px solid; }}
            .Critical {{ border-color: #ff3366; background: #ffe6e9; }}
            .High {{ border-color: #ff6600; background: #fff0e6; }}
        </style>
        </head>
        <body>
        <div class="container">
            <h1>🔒 RedTeamKa Security Report</h1>
            <p>Generated: {datetime.now().isoformat()}</p>
            <hr>
            <h2>Findings Summary</h2>
            {self._findings_to_html(report.get('data', {}).get('findings', []))}
        </div>
        </body>
        </html>
        """
        with open(pdf_path, 'w') as f:
            f.write(html_content)
        return pdf_path
    
    def _generate_summary(self, scans):
        total_findings = sum(len(s.get('findings', [])) for s in scans)
        return f"Assessment completed on {len(scans)} targets with {total_findings} findings."
    
    def _aggregate_findings(self, scans):
        all_findings = []
        for scan in scans:
            all_findings.extend(scan.get('findings', []))
        return all_findings
    
    def _calculate_stats(self, scans):
        findings = self._aggregate_findings(scans)
        return {
            'total_scans': len(scans),
            'total_findings': len(findings),
            'critical': len([f for f in findings if f.get('severity') == 'Critical']),
            'high': len([f for f in findings if f.get('severity') == 'High'])
        }
    
    def _findings_to_html(self, findings):
        if not findings:
            return '<p>No findings discovered.</p>'
        html = '<ul>'
        for f in findings:
            html += f'<li><strong>{f.get("title")}</strong> - {f.get("severity")}</li>'
        html += '</ul>'
        return html


class AIAnalyzer:
    """Built-in AI Analyzer"""
    
    def analyze_results(self, results):
        findings = results.get('findings', [])
        risk_score = self._calculate_risk_score(findings)
        
        return {
            'risk_score': risk_score,
            'summary': self._generate_summary(findings, risk_score),
            'recommendations': self._generate_recommendations(findings, risk_score),
            'priority_findings': self._get_priority_findings(findings)
        }
    
    def _calculate_risk_score(self, findings):
        if not findings:
            return 0
        weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2}
        total = sum(weights.get(f.get('severity', 'Low'), 1) for f in findings)
        max_possible = len(findings) * 10
        return round((total / max_possible) * 100) if max_possible > 0 else 0
    
    def _generate_summary(self, findings, risk_score):
        if not findings:
            return 'No vulnerabilities detected. System appears secure.'
        critical = len([f for f in findings if f.get('severity') == 'Critical'])
        if risk_score > 70:
            return f'CRITICAL RISK: {critical} critical vulnerabilities require immediate attention.'
        elif risk_score > 40:
            return f'HIGH RISK: Multiple vulnerabilities detected that need remediation.'
        return f'MEDIUM RISK: {len(findings)} vulnerabilities found requiring review.'
    
    def _generate_recommendations(self, findings, risk_score):
        recs = []
        if risk_score > 70:
            recs.append('Immediately patch all critical vulnerabilities')
            recs.append('Consider temporary isolation of affected systems')
        if risk_score > 40:
            recs.append('Prioritize remediation of high-severity findings')
            recs.append('Review and update firewall rules')
        recs.append('Conduct regular security assessments')
        recs.append('Implement security monitoring and logging')
        return recs
    
    def _get_priority_findings(self, findings):
        return [f for f in findings if f.get('severity') in ['Critical', 'High']][:5]


# ============================================
# USER DATABASE
# ============================================

class User(UserMixin):
    def __init__(self, id, username, password_hash, role, email):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.email = email

users = {}
scans = {}
findings = []
reports = []

default_users = {
    'pentest': {'password': 'RedTeamKa@2024', 'role': 'pentest', 'email': 'pentest@redteamka.local'},
    'client': {'password': 'Client@2024', 'role': 'client', 'email': 'client@redteamka.local'}
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

# Initialize engines
scan_engine = ScanEngine()
exploit_engine = ExploitEngine()
report_engine = ReportEngine()
ai_analyzer = AIAnalyzer()

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
    scan_type = data.get('scan_type', 'quick')
    options = data.get('options', {})
    
    scan_id = str(uuid.uuid4())
    
    def run_scan():
        try:
            socketio.emit('scan_status', {'scan_id': scan_id, 'status': 'running', 'message': f'Starting {scan_type} scan on {target}'})
            
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
            
            socketio.emit('scan_status', {'scan_id': scan_id, 'status': 'analyzing', 'message': 'AI analyzing scan results...'})
            ai_analysis = ai_analyzer.analyze_results(results)
            findings_list = scan_engine.generate_findings(results)
            
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
            
            for finding in findings_list:
                finding['scan_id'] = scan_id
                finding['scan_target'] = target
                findings.append(finding)
            
            socketio.emit('scan_completed', {
                'scan_id': scan_id,
                'findings_count': len(findings_list),
                'message': f'Scan completed on {target}'
            })
            
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
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'scan_id': scan_id, 'message': 'Scan started successfully'})

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
@login_required
def get_scan_status(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify({'status': scan.get('status'), 'message': scan.get('message', 'Processing...')})

@app.route('/api/scan/results/<scan_id>', methods=['GET'])
@login_required
def get_scan_results(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
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
    result = exploit_engine.run_exploit(data.get('exploit'), data.get('target'), data.get('options', {}))
    return jsonify({'success': True, 'result': result})

@app.route('/api/exploits/list', methods=['GET'])
@login_required
def list_exploits():
    return jsonify(exploit_engine.list_available_exploits())

# ============================================
# REPORT ROUTES
# ============================================

@app.route('/api/report/generate', methods=['POST'])
@login_required
def generate_report():
    data = request.json
    scan_ids = data.get('scan_ids', [])
    report_type = data.get('type', 'executive')
    
    report_scans = []
    for scan_id in scan_ids:
        scan = scans.get(scan_id)
        if scan and (scan['created_by'] == current_user.username or current_user.role == 'pentest'):
            report_scans.append(scan)
    
    if not report_scans:
        return jsonify({'error': 'No valid scans found'}), 404
    
    report_data = report_engine.generate_report(report_scans, report_type, current_user.username)
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
    
    return jsonify({'success': True, 'report_id': report_id, 'report': report_data})

@app.route('/api/report/download/<report_id>', methods=['GET'])
@login_required
def download_report(report_id):
    report = next((r for r in reports if r['id'] == report_id), None)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    pdf_path = report_engine.generate_pdf(report)
    return send_from_directory(os.path.dirname(pdf_path), os.path.basename(pdf_path), as_attachment=True)

@app.route('/api/reports', methods=['GET'])
@login_required
def get_reports():
    if current_user.role == 'pentest':
        return jsonify(reports)
    return jsonify([r for r in reports if r['generated_by'] == current_user.username])

# ============================================
# FINDINGS ROUTES
# ============================================

@app.route('/api/findings', methods=['GET'])
@login_required
def get_findings():
    if current_user.role == 'pentest':
        return jsonify(findings)
    
    user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
    user_scan_ids = [s['id'] for s in user_scans]
    return jsonify([f for f in findings if f['scan_id'] in user_scan_ids])

# ============================================
# DASHBOARD STATS
# ============================================

@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    if current_user.role == 'pentest':
        total_scans = len(scans)
        critical = len([f for f in findings if f.get('severity') == 'Critical'])
        high = len([f for f in findings if f.get('severity') == 'High'])
        unique_targets = len(set([s['target'] for s in scans.values()]))
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
        user_scan_ids = [s['id'] for s in user_scans]
        user_findings = [f for f in findings if f['scan_id'] in user_scan_ids]
        total_scans = len(user_scans)
        critical = len([f for f in user_findings if f.get('severity') == 'Critical'])
        high = len([f for f in user_findings if f.get('severity') == 'High'])
        unique_targets = len(set([s['target'] for s in user_scans]))
    
    return jsonify({
        'total_scans': total_scans,
        'critical_findings': critical,
        'high_findings': high,
        'total_findings': len(findings) if current_user.role == 'pentest' else critical + high,
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
# TOOLS & HEALTH
# ============================================

@app.route('/api/tools', methods=['GET'])
@login_required
def get_available_tools():
    tools = [
        {'name': 'Nmap', 'description': 'Network discovery and scanning', 'category': 'network'},
        {'name': 'Metasploit', 'description': 'Exploitation framework', 'category': 'exploit'},
        {'name': 'Hydra', 'description': 'Password brute-forcing', 'category': 'auth'},
        {'name': 'SQLmap', 'description': 'SQL injection detection', 'category': 'web'},
        {'name': 'Gobuster', 'description': 'Directory brute-forcing', 'category': 'web'},
        {'name': 'Nikto', 'description': 'Web vulnerability scanner', 'category': 'web'}
    ]
    return jsonify(tools)

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
    ║  🛠️  Integrated Tools: Nmap, Metasploit, Hydra, SQLmap, Gobuster ║
    ║  🤖 AI Features: Risk scoring, Smart recommendations             ║
    ║                                                                   ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║  ⚠️  EDUCATIONAL PURPOSE ONLY - Use responsibly                 ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    socketio.run(app, host='0.0.0.0', port=8888, debug=False, allow_unsafe_werkzeug=True)
