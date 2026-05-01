"""Scan management routes"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
import uuid
import threading

scan_bp = Blueprint('scan', __name__)

# Global storage (in production, use database)
scans = {}
scan_engine = None

def init_scan_engine(engine):
    """Initialize scan engine from main app"""
    global scan_engine
    scan_engine = engine

@scan_bp.route('/scan/start', methods=['POST'])
@login_required
def start_scan():
    """Start a new security scan"""
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
            # Update status via socket would go here
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
            
            scans[scan_id] = {
                'id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'status': 'completed',
                'results': results,
                'findings': results.get('findings', []),
                'created_by': current_user.username,
                'created_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            }
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
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })

@scan_bp.route('/scan/status/<scan_id>', methods=['GET'])
@login_required
def get_scan_status(scan_id):
    """Get scan status"""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'status': scan.get('status'),
        'message': scan.get('message', 'Processing...')
    })

@scan_bp.route('/scan/results/<scan_id>', methods=['GET'])
@login_required
def get_scan_results(scan_id):
    """Get scan results"""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    if scan['created_by'] != current_user.username and current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    return jsonify(scan)

@scan_bp.route('/scans', methods=['GET'])
@login_required
def get_all_scans():
    """Get all scans (filtered by role)"""
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
        'created_at': s['created_at']
    } for s in user_scans])

@scan_bp.route('/scan/delete/<scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    """Delete a scan (pentest only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    if scan_id in scans:
        del scans[scan_id]
        return jsonify({'success': True, 'message': 'Scan deleted'})
    
    return jsonify({'error': 'Scan not found'}), 404