"""Findings management routes"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

findings_bp = Blueprint('findings', __name__)

# Global storage
findings = []
scans = None

def init_findings(findings_list, scans_dict):
    """Initialize findings from main app"""
    global findings, scans
    findings = findings_list
    scans = scans_dict

@findings_bp.route('/findings', methods=['GET'])
@login_required
def get_findings():
    """Get all findings (filtered by role)"""
    if current_user.role == 'pentest':
        return jsonify(findings)
    
    user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
    user_scan_ids = [s['id'] for s in user_scans]
    user_findings = [f for f in findings if f.get('scan_id') in user_scan_ids]
    
    return jsonify(user_findings)

@findings_bp.route('/findings/by-severity', methods=['GET'])
@login_required
def get_findings_by_severity():
    """Get findings filtered by severity"""
    severity = request.args.get('severity', 'all')
    
    if current_user.role == 'pentest':
        user_findings = findings
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
        user_scan_ids = [s['id'] for s in user_scans]
        user_findings = [f for f in findings if f.get('scan_id') in user_scan_ids]
    
    if severity != 'all':
        user_findings = [f for f in user_findings if f.get('severity', '').lower() == severity.lower()]
    
    return jsonify(user_findings)

@findings_bp.route('/findings/acknowledge/<finding_id>', methods=['POST'])
@login_required
def acknowledge_finding(finding_id):
    """Acknowledge a finding (client action)"""
    finding = next((f for f in findings if f.get('id') == finding_id), None)
    
    if not finding:
        return jsonify({'error': 'Finding not found'}), 404
    
    finding['acknowledged'] = True
    finding['acknowledged_by'] = current_user.username
    finding['acknowledged_at'] = __import__('datetime').datetime.now().isoformat()
    
    return jsonify({'success': True, 'message': 'Finding acknowledged'})

@findings_bp.route('/findings/export', methods=['GET'])
@login_required
def export_findings():
    """Export findings as CSV"""
    import csv
    import io
    
    if current_user.role == 'pentest':
        user_findings = findings
    else:
        user_scans = [s for s in scans.values() if s['created_by'] == current_user.username]
        user_scan_ids = [s['id'] for s in user_scans]
        user_findings = [f for f in findings if f.get('scan_id') in user_scan_ids]
    
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