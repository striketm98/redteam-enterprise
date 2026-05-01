"""Administrative routes (pentest only)"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

admin_bp = Blueprint('admin', __name__)

# Global storage
users = None
scans = None
findings = None

def init_admin(users_dict, scans_dict, findings_list):
    """Initialize admin with data from main app"""
    global users, scans, findings
    users = users_dict
    scans = scans_dict
    findings = findings_list

@admin_bp.route('/admin/users', methods=['GET'])
@login_required
def get_users():
    """Get all users (pentest only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    user_list = []
    for username, user in users.items():
        user_list.append({
            'username': user.username,
            'role': user.role,
            'email': user.email,
            'created_at': getattr(user, 'created_at', None)
        })
    
    return jsonify(user_list)

@admin_bp.route('/admin/users', methods=['POST'])
@login_required
def create_user():
    """Create new user (pentest only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    from werkzeug.security import generate_password_hash
    from flask_login import UserMixin
    import uuid
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'client')
    email = data.get('email')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if username in users:
        return jsonify({'error': 'Username already exists'}), 400
    
    class NewUser(UserMixin):
        def __init__(self, id, username, password_hash, role, email):
            self.id = id
            self.username = username
            self.password_hash = password_hash
            self.role = role
            self.email = email
    
    user_id = str(uuid.uuid4())
    users[username] = NewUser(
        id=user_id,
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
        email=email
    )
    
    return jsonify({
        'success': True,
        'user': {'username': username, 'role': role, 'email': email}
    }), 201

@admin_bp.route('/admin/users/<username>', methods=['DELETE'])
@login_required
def delete_user(username):
    """Delete user (pentest only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    if username not in users:
        return jsonify({'error': 'User not found'}), 404
    
    if username == current_user.username:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    del users[username]
    return jsonify({'success': True, 'message': 'User deleted'})

@admin_bp.route('/admin/system/stats', methods=['GET'])
@login_required
def get_system_stats():
    """Get system statistics (pentest only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    import platform
    import psutil
    
    return jsonify({
        'system': platform.system(),
        'python_version': platform.python_version(),
        'total_scans': len(scans),
        'total_findings': len(findings),
        'total_users': len(users),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent
    })

@admin_bp.route('/admin/system/cleanup', methods=['POST'])
@login_required
def cleanup_system():
    """Clean up old data (pentest only)"""
    if current_user.role != 'pentest':
        return jsonify({'error': 'Permission denied'}), 403
    
    from datetime import datetime, timedelta
    
    cutoff = datetime.now() - timedelta(days=30)
    cutoff_str = cutoff.isoformat()
    
    # Remove old scans
    old_scans = [sid for sid, scan in scans.items() 
                 if scan.get('created_at', '') < cutoff_str]
    
    for sid in old_scans:
        del scans[sid]
    
    return jsonify({
        'success': True,
        'message': f'Removed {len(old_scans)} old scans'
    })