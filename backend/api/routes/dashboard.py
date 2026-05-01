"""Dashboard statistics routes"""

from flask import Blueprint, jsonify
from flask_login import login_required, current_user

dashboard_bp = Blueprint('dashboard', __name__)

# Global storage
scans = None
findings = None

def init_dashboard(scans_dict, findings_list):
    """Initialize dashboard with data from main app"""
    global scans, findings
    scans = scans_dict
    findings = findings_list

@dashboard_bp.route('/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    """Get dashboard statistics"""
    if current_user.role == 'pentest':
        total_scans = len(scans)
        completed_scans = len([s for s in scans.values() if s.get('status') == 'completed'])
        critical_findings = len([f for f in findings if f.get('severity') == 'Critical'])
        high_findings = len([f for f in findings if f.get('severity') == 'High'])
        medium_findings = len([f for f in findings if f.get('severity') == 'Medium'])
        low_findings = len([f for f in findings if f.get('severity') == 'Low'])
        total_findings = len(findings)
        unique_targets = len(set([s.get('target') for s in scans.values()]))
    else:
        user_scans = [s for s in scans.values() if s.get('created_by') == current_user.username]
        user_scan_ids = [s.get('id') for s in user_scans]
        user_findings = [f for f in findings if f.get('scan_id') in user_scan_ids]
        
        total_scans = len(user_scans)
        completed_scans = len([s for s in user_scans if s.get('status') == 'completed'])
        critical_findings = len([f for f in user_findings if f.get('severity') == 'Critical'])
        high_findings = len([f for f in user_findings if f.get('severity') == 'High'])
        medium_findings = len([f for f in user_findings if f.get('severity') == 'Medium'])
        low_findings = len([f for f in user_findings if f.get('severity') == 'Low'])
        total_findings = len(user_findings)
        unique_targets = len(set([s.get('target') for s in user_scans]))
    
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

@dashboard_bp.route('/dashboard/recent', methods=['GET'])
@login_required
def get_recent_activity():
    """Get recent scan activity"""
    if current_user.role == 'pentest':
        recent_scans = sorted(
            scans.values(), 
            key=lambda x: x.get('created_at', ''), 
            reverse=True
        )[:10]
    else:
        user_scans = [s for s in scans.values() if s.get('created_by') == current_user.username]
        recent_scans = sorted(
            user_scans, 
            key=lambda x: x.get('created_at', ''), 
            reverse=True
        )[:10]
    
    return jsonify([{
        'id': s.get('id'),
        'target': s.get('target'),
        'scan_type': s.get('scan_type'),
        'status': s.get('status'),
        'created_at': s.get('created_at'),
        'findings_count': len(s.get('findings', []))
    } for s in recent_scans])

@dashboard_bp.route('/dashboard/trends', methods=['GET'])
@login_required
def get_trends():
    """Get security trends over time"""
    import datetime as dt
    
    if current_user.role == 'pentest':
        user_scans = list(scans.values())
    else:
        user_scans = [s for s in scans.values() if s.get('created_by') == current_user.username]
    
    # Group by date for the last 30 days
    trends = {}
    today = dt.datetime.now().date()
    
    for i in range(30):
        date = today - dt.timedelta(days=i)
        date_str = date.isoformat()
        trends[date_str] = {'scans': 0, 'findings': 0}
    
    for scan in user_scans:
        created = dt.datetime.fromisoformat(scan.get('created_at', '')).date()
        if created >= today - dt.timedelta(days=30):
            date_str = created.isoformat()
            trends[date_str]['scans'] += 1
            trends[date_str]['findings'] += len(scan.get('findings', []))
    
    return jsonify({
        'dates': list(trends.keys()),
        'scans': [trends[d]['scans'] for d in trends.keys()],
        'findings': [trends[d]['findings'] for d in trends.keys()]
    })