"""Report generation routes"""

from flask import Blueprint, request, jsonify, send_from_directory
from flask_login import login_required, current_user
from datetime import datetime
import uuid
import os

report_bp = Blueprint('report', __name__)

# Global storage
reports = []
report_engine = None
scans = None

def init_report_engine(engine, scans_dict):
    """Initialize report engine from main app"""
    global report_engine, scans
    report_engine = engine
    scans = scans_dict

@report_bp.route('/report/generate', methods=['POST'])
@login_required
def generate_report():
    """Generate a security report"""
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

@report_bp.route('/report/download/<report_id>', methods=['GET'])
@login_required
def download_report(report_id):
    """Download a generated report"""
    report = next((r for r in reports if r['id'] == report_id), None)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    
    pdf_path = report_engine.generate_pdf(report)
    directory = os.path.dirname(pdf_path)
    filename = os.path.basename(pdf_path)
    
    return send_from_directory(directory, filename, as_attachment=True)

@report_bp.route('/reports', methods=['GET'])
@login_required
def get_reports():
    """Get all reports (filtered by role)"""
    if current_user.role == 'pentest':
        user_reports = reports
    else:
        user_reports = [r for r in reports if r['generated_by'] == current_user.username]
    
    return jsonify(user_reports)

@report_bp.route('/report/delete/<report_id>', methods=['DELETE'])
@login_required
def delete_report(report_id):
    """Delete a report (pentest only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    global reports
    reports = [r for r in reports if r['id'] != report_id]
    return jsonify({'success': True, 'message': 'Report deleted'})