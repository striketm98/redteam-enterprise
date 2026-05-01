from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model with role-based access control"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='client')  # 'pentest' or 'client'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_permission(self, permission):
        """Check if user has specific permission"""
        permissions = {
            'pentest': ['scan', 'create_report', 'delete_report', 'manage_users', 'view_all_reports'],
            'client': ['view_own_reports', 'download_report']
        }
        return permission in permissions.get(self.role, [])
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Scan(db.Model):
    """Scan model to store scan results"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = db.Column(db.String(200), nullable=False)
    scan_type = db.Column(db.String(50))  # nmap, gobuster, nikto, full
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    results = db.Column(db.Text)
    findings_count = db.Column(db.Integer, default=0)
    created_by = db.Column(db.String(36), db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'findings_count': self.findings_count,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Finding(db.Model):
    """Security findings model"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20))  # Critical, High, Medium, Low, Info
    description = db.Column(db.Text)
    remediation = db.Column(db.Text)
    cvss_score = db.Column(db.Float, default=0)
    scan_id = db.Column(db.String(36), db.ForeignKey('scan.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score
        }

def init_db():
    """Initialize database with default users"""
    db.create_all()
    
    # Create default pentest user if not exists
    if not User.query.filter_by(role='pentest').first():
        pentest_user = User(
            username='pentest',
            email='pentest@redteam.local',
            role='pentest'
        )
        pentest_user.set_password('Pentest@123')
        db.session.add(pentest_user)
    
    # Create default client user if not exists
    if not User.query.filter_by(role='client').first():
        client_user = User(
            username='client',
            email='client@redteam.local',
            role='client'
        )
        client_user.set_password('Client@123')
        db.session.add(client_user)
    
    db.session.commit()
    print("✅ Database initialized with default users")
