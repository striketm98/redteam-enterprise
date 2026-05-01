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
# CORE ENGINE CLASSES
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
            
            cmd = f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -t 30 -q 2>/dev/null"
            output = self._run_command(cmd)
            results['directories'] = self._parse_directories(output)
            
            sensitive = ['admin', 'login', 'backup', 'config', '.git', 'wp-admin']
            for dir_entry in results['directories']:
                for sens in sensitive:
                    if sens in dir_entry.lower():
                        results['findings'].append({
                            'title': f'Sensitive Directory Found: {sens}',
                            'severity': 'Medium',
                            'description': f'Found potentially sensitive directory: {dir_entry}',
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
            {'name': 'heartbleed', 'description': 'OpenSSL info disclosure', 'risk': 'High'},
            {'name': 'dirtycow', 'description': 'Linux privilege escalation', 'risk': 'High'},
            {'name': 'struts2', 'description': 'Apache Struts2 RCE', 'risk': 'Critical'}
        ]


class ReportEngine:
    """Built-in Report Engine"""
    
    def generate_report(self, scans_data, report_type, username):
        report = {
            'title': f'Security Assessment Report - {report_type.upper()}',
            'generated_by': username,
            'generated_at': datetime.now().isoformat(),
            'report_type': report_type,
            'summary': self._generate_summary(scans_data),
            'findings': self._aggregate_findings(scans_data),
            'statistics': self._calculate_stats(scans_data)
        }
        return report
    
    def generate_pdf(self, report):
        reports_dir = '/app/reports'
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, f'report_{report.get("id", "unknown")}.html')
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{report.get('title', 'Security Report')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .container {{ max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 10px; }}
                h1 {{ color: #ff3366; border-bottom: 2px solid #ff3366; padding-bottom: 10px; }}
                h2 {{ color: #333; margin-top: 30px; }}
                .finding {{ margin: 15px 0; padding: 15px; border-left: 4px solid; border-radius: 4px; }}
                .Critical {{ border-color: #ff3366; background: #ffe6e9; }}
                .High {{ border-color: #ff6600; background: #fff0e6; }}
                .Medium {{ border-color: #ffaa00; background: #fff8e6; }}
                .Low {{ border-color: #00ff88; background: #e6fff0; }}
                .severity-badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
                .severity-Critical {{ background: #ff3366; color: white; }}
                .severity-High {{ background: #ff6600; color: white; }}
                .footer {{ margin-top: 40px; text-align: center; color: #999; font-size: 12px; border-top: 1px solid #ddd; padding-top: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #f0f0f0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 RedTeamKa Security Assessment Report</h1>
                <p><strong>Generated:</strong> {datetime.now().isoformat()}</p>
                <p><strong>Generated By:</strong> {report.get('generated_by', 'Unknown')}</p>
                <hr>
                
                <h2>📊 Executive Summary</h2>
                <p>{report.get('data', {}).get('summary', 'No summary available')}</p>
                
                <h2>📈 Statistics</h2>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    <tr><td>Total Scans</td><td>{report.get('data', {}).get('statistics', {}).get('total_scans', 0)}</td></tr>
                    <tr><td>Total Findings</td><td>{report.get('data', {}).get('statistics', {}).get('total_findings', 0)}</td></tr>
                    <tr><td>Critical Findings</td><td>{report.get('data', {}).get('statistics', {}).get('critical', 0)}</td></tr>
                    <tr><td>High Findings</td><td>{report.get('data', {}).get('statistics', {}).get('high', 0)}</td></tr>
                </table>
                
                <h2>🔍 Detailed Findings</h2>
                {self._findings_to_html(report.get('data', {}).get('findings', []))}
                
                <div class="footer">
                    <p>This report was automatically generated by RedTeamKa Enterprise Platform</p>
                    <p>Confidential - For authorized use only</p>
                </div>
            </div>
        </body>
        </html>
        """
        with open(pdf_path, 'w') as f:
            f.write(html_content)
        return pdf_path
    
    def _generate_summary(self, scans_data):
        total_findings = sum(len(s.get('findings', [])) for s in scans_data)
        critical = sum(1 for s in scans_data for f in s.get('findings', []) if f.get('severity') == 'Critical')
        
        if critical > 0:
            return f"CRITICAL: Assessment completed on {len(scans_data)} targets with {total_findings} findings, including {critical} critical vulnerabilities that require immediate attention."
        return f"Assessment completed on {len(scans_data)} targets with {total_findings} findings."
    
    def _aggregate_findings(self, scans_data):
        all_findings = []
        for scan in scans_data:
            all_findings.extend(scan.get('findings', []))
        return all_findings
    
    def _calculate_stats(self, scans_data):
        findings = self._aggregate_findings(scans_data)
        return {
            'total_scans': len(scans_data),
            'total_findings': len(findings),
            'critical': len([f for f in findings if f.get('severity') == 'Critical']),
            'high': len([f for f in findings if f.get('severity') == 'High']),
            'medium': len([f for f in findings if f.get('severity') == 'Medium']),
            'low': len([f for f in findings if f.get('severity') == 'Low'])
        }
    
    def _findings_to_html(self, findings):
        if not findings:
            return '<p>✅ No findings discovered during this assessment.</p>'
        
        html = '<ul style="list-style: none; padding: 0;">'
        for f in findings:
            severity = f.get('severity', 'Low')
            html += f'''
            <li class="finding {severity}" style="margin-bottom: 15px; padding: 15px; border-left: 4px solid; border-radius: 4px;">
                <strong>{f.get('title', 'Untitled Finding')}</strong><br>
                <span class="severity-badge severity-{severity}">{severity}</span>
                <p style="margin-top: 10px;"><strong>Description:</strong> {f.get('description', 'N/A')}</p>
                <p><strong>Remediation:</strong> {f.get('remediation', 'Apply security best practices')}</p>
            </li>
            '''
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
        high = len([f for f in findings if f.get('severity') == 'High'])
        
        if risk_score >= 80:
            return f'🚨 CRITICAL RISK: {critical} critical vulnerabilities require immediate attention. System at high risk of compromise.'
        elif risk_score >= 60:
            return f'⚠️ HIGH RISK: {critical} critical and {high} high severity vulnerabilities detected.'
        elif risk_score >= 40:
            return f'📊 MEDIUM RISK: Multiple vulnerabilities detected that need remediation.'
        else:
            return f'✅ LOW RISK: {len(findings)} minor vulnerabilities found for review.'
    
    def _generate_recommendations(self, findings, risk_score):
        recs = []
        
        if risk_score >= 80:
            recs.append('🔴 IMMEDIATE: Patch all critical vulnerabilities within 24 hours')
            recs.append('🔴 IMMEDIATE: Consider temporary isolation of affected systems')
            recs.append('📋 Conduct emergency incident response review')
        elif risk_score >= 60:
            recs.append('🟠 HIGH PRIORITY: Remediate critical and high findings within 7 days')
            recs.append('🟠 Review and update firewall rules')
            recs.append('📋 Implement additional monitoring for affected services')
        elif risk_score >= 40:
            recs.append('🟡 MEDIUM PRIORITY: Address findings in next sprint')
            recs.append('🟡 Review security configurations')
        else:
            recs.append('🟢 LOW PRIORITY: Follow standard patch management cycles')
        
        recs.append('📊 Schedule follow-up assessment after remediation')
        recs.append('🔒 Implement principle of least privilege')
        recs.append('📝 Document all findings and remediation actions')
        
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
# API ROUTES - AUTHENTICATION
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

@app.route('/api/auth/verify', methods=['GET'])
@login_required
def verify_token():
    return jsonify({
        'valid': True,
        'user': {
            'username': current_user.username,
            'role': current_user.role
        }
    })

# ============================================
# API ROUTES - SCANNING
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
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
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

@app.route('/api/scan/delete/<scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    if current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    if scan_id in scans:
        del scans[scan_id]
        return jsonify({'success': True, 'message': 'Scan deleted'})
    
    return jsonify({'error': 'Scan not found'}), 404

# ============================================
# API ROUTES - EXPLOITS
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
    
    if not exploit_name or not target:
        return jsonify({'error': 'Exploit name and target required'}), 400
    
    result = exploit_engine.run_exploit(exploit_name, target, options)
    return jsonify({'success': True, 'result': result})

@app.route('/api/exploits/list', methods=['GET'])
@login_required
def list_exploits():
    return jsonify(exploit_engine.list_available_exploits())

@app.route('/api/exploit/info/<exploit_name>', methods=['GET'])
@login_required
def get_exploit_info(exploit_name):
    exploits = exploit_engine.list_available_exploits()
    exploit = next((e for e in exploits if e['name'] == exploit_name), None)
    
    if not exploit:
        return jsonify({'error': 'Exploit not found'}), 404
    
    return jsonify(exploit)

# ============================================
# API ROUTES - REPORTS
# ============================================

@app.route('/api/report/generate', methods=['POST'])
@login_required
def generate_report():
    data = request.json
    scan_ids = data.get('scan_ids', [])
    report_type = data.get('type', 'executive')
    
    if not scan_ids:
        return jsonify({'error': 'No scan IDs provided'}), 400
    
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
    
    pdf_path = report_engine.generate_pdf(report)
    return send_from_directory(os.path.dirname(pdf_path), os.path.basename(pdf_path), as_attachment=True)

@app.route('/api/reports', methods=['GET'])
@login_required
def get_reports():
    if current_user.role == 'pentest':
        return jsonify(reports)
    return jsonify([r for r in reports if r['generated_by'] == current_user.username])

@app.route('/api/report/delete/<report_id>', methods=['DELETE'])
@login_required
def delete_report(report_id):
    if current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    global reports
    reports = [r for r in reports if r['id'] != report_id]
    return jsonify({'success': True, 'message': 'Report deleted'})

# ============================================
# API ROUTES - FINDINGS
# ============================================

@app.route('/api/findings', methods=['GET'])
@login_required
def get_findings():
    if current_user.role == 'pentest':
        return jsonify(findings)
    
    user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
    user_scan_ids = [s['id'] for s in user_scans]
    return jsonify([f for f in findings if f['scan_id'] in user_scan_ids])

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

@app.route('/api/findings/export', methods=['GET'])
@login_required
def export_findings():
    import csv
    import io
    
    if current_user.role == 'pentest':
        user_findings = findings
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
        user_scan_ids = [s['id'] for s in user_scans]
        user_findings = [f for f in findings if f['scan_id'] in user_scan_ids]
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Title', 'Severity', 'Description', 'Remediation', 'Scan Target', 'Date'])
    
    for f in user_findings:
        writer.writerow([
            f.get('title', ''),
            f.get('severity', ''),
            f.get('description', ''),
            f.get('remediation', ''),
            f.get('scan_target', ''),
            f.get('created_at', '')[:10]
        ])
    
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename=findings_export.csv'
    }

# ============================================
# API ROUTES - DASHBOARD
# ============================================

@app.route('/api/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    if current_user.role == 'pentest':
        total_scans = len(scans)
        completed_scans = len([s for s in scans.values() if s.get('status') == 'completed'])
        critical = len([f for f in findings if f.get('severity') == 'Critical'])
        high = len([f for f in findings if f.get('severity') == 'High'])
        medium = len([f for f in findings if f.get('severity') == 'Medium'])
        low = len([f for f in findings if f.get('severity') == 'Low'])
        total_findings = len(findings)
        unique_targets = len(set([s['target'] for s in scans.values()]))
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
        user_scan_ids = [s['id'] for s in user_scans]
        user_findings = [f for f in findings if f['scan_id'] in user_scan_ids]
        total_scans = len(user_scans)
        completed_scans = len([s for s in user_scans if s.get('status') == 'completed'])