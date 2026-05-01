"""Authentication routes"""

from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from datetime import datetime
import uuid

auth_bp = Blueprint('auth', __name__)

# User storage (in production, use database)
users = {}

def init_users(users_dict):
    """Initialize users from main app"""
    global users
    users = users_dict

@auth_bp.route('/auth/login', methods=['POST'])
def login():
    """Authenticate user and return token"""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({
                'success': False, 
                'message': 'Username and password required'
            }), 400
        
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
        
        return jsonify({
            'success': False, 
            'message': 'Invalid credentials'
        }), 401
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'message': str(e)
        }), 500

@auth_bp.route('/auth/logout', methods=['POST'])
@login_required
def logout():
    """Logout user"""
    logout_user()
    return jsonify({
        'success': True, 
        'message': 'Logged out successfully'
    })

@auth_bp.route('/auth/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current authenticated user"""
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'role': current_user.role,
        'email': current_user.email
    })

@auth_bp.route('/auth/verify', methods=['GET'])
@login_required
def verify_token():
    """Verify if token is valid"""
    return jsonify({
        'valid': True,
        'user': {
            'username': current_user.username,
            'role': current_user.role
        }
    })