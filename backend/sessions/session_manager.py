"""
Session Manager - Handle user sessions and state management
"""

import uuid
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from collections import defaultdict
import threading
import os


class SessionManager:
    """Manage user sessions and application state"""
    
    def __init__(self, session_dir: str = None):
        self.sessions = {}
        self.user_sessions = defaultdict(list)
        self.session_timeout = 3600  # 1 hour default
        self.max_sessions_per_user = 5
        self.session_dir = session_dir or '/app/sessions/data'
        
        # Ensure session directory exists
        os.makedirs(self.session_dir, exist_ok=True)
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
    
    def create_session(self, user_id: str, user_data: Dict) -> str:
        """Create a new session for a user"""
        # Check session limit
        if len(self.user_sessions[user_id]) >= self.max_sessions_per_user:
            # Remove oldest session
            oldest_session = self.user_sessions[user_id].pop(0)
            self._remove_session(oldest_session)
        
        # Generate session token
        session_token = self._generate_session_token(user_id)
        
        session = {
            'token': session_token,
            'user_id': user_id,
            'user_data': user_data,
            'created_at': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(seconds=self.session_timeout)).isoformat(),
            'is_active': True,
            'ip_address': None,
            'user_agent': None,
            'data': {}
        }
        
        self.sessions[session_token] = session
        self.user_sessions[user_id].append(session_token)
        
        # Persist to disk
        self._save_session(session_token)
        
        return session_token
    
    def get_session(self, session_token: str) -> Optional[Dict]:
        """Get session by token"""
        session = self.sessions.get(session_token)
        
        if not session:
            # Try to load from disk
            session = self._load_session(session_token)
            if session:
                self.sessions[session_token] = session
        
        if session and self._is_session_valid(session):
            # Update last activity
            session['last_activity'] = datetime.now().isoformat()
            session['expires_at'] = (datetime.now() + timedelta(seconds=self.session_timeout)).isoformat()
            self.sessions[session_token] = session
            self._save_session(session_token)
            return session
        
        return None
    
    def update_session(self, session_token: str, data: Dict) -> bool:
        """Update session data"""
        session = self.get_session(session_token)
        if session:
            session['data'].update(data)
            session['last_activity'] = datetime.now().isoformat()
            self.sessions[session_token] = session
            self._save_session(session_token)
            return True
        return False
    
    def delete_session(self, session_token: str) -> bool:
        """Delete a session"""
        return self._remove_session(session_token)
    
    def delete_user_sessions(self, user_id: str) -> int:
        """Delete all sessions for a user"""
        count = 0
        for session_token in self.user_sessions.get(user_id, []):
            if self._remove_session(session_token):
                count += 1
        
        self.user_sessions[user_id] = []
        return count
    
    def get_user_sessions(self, user_id: str) -> List[Dict]:
        """Get all active sessions for a user"""
        sessions = []
        for session_token in self.user_sessions.get(user_id, []):
            session = self.get_session(session_token)
            if session:
                sessions.append({
                    'token': session_token[:8] + '...',
                    'created_at': session['created_at'],
                    'last_activity': session['last_activity'],
                    'expires_at': session['expires_at']
                })
        return sessions
    
    def extend_session(self, session_token: str) -> bool:
        """Extend session timeout"""
        session = self.get_session(session_token)
        if session:
            session['expires_at'] = (datetime.now() + timedelta(seconds=self.session_timeout)).isoformat()
            self.sessions[session_token] = session
            self._save_session(session_token)
            return True
        return False
    
    def is_session_valid(self, session_token: str) -> bool:
        """Check if session is valid"""
        session = self.get_session(session_token)
        return session is not None and self._is_session_valid(session)
    
    def get_active_sessions_count(self) -> int:
        """Get total number of active sessions"""
        return len(self.sessions)
    
    def get_user_sessions_count(self, user_id: str) -> int:
        """Get number of sessions for a user"""
        return len(self.user_sessions.get(user_id, []))
    
    def _generate_session_token(self, user_id: str) -> str:
        """Generate unique session token"""
        raw = f"{user_id}_{datetime.now().timestamp()}_{uuid.uuid4()}"
        return hashlib.sha256(raw.encode()).hexdigest()
    
    def _is_session_valid(self, session: Dict) -> bool:
        """Check if session is still valid"""
        if not session.get('is_active', False):
            return False
        
        expires_at = datetime.fromisoformat(session['expires_at'])
        if datetime.now() > expires_at:
            return False
        
        return True
    
    def _remove_session(self, session_token: str) -> bool:
        """Remove session from memory and disk"""
        if session_token in self.sessions:
            session = self.sessions[session_token]
            user_id = session.get('user_id')
            
            # Remove from user sessions list
            if user_id and session_token in self.user_sessions[user_id]:
                self.user_sessions[user_id].remove(session_token)
            
            # Remove from memory
            del self.sessions[session_token]
            
            # Remove from disk
            self._delete_session_file(session_token)
            
            return True
        return False
    
    def _save_session(self, session_token: str):
        """Save session to disk"""
        if session_token in self.sessions:
            session_file = os.path.join(self.session_dir, f"{session_token}.json")
            try:
                with open(session_file, 'w') as f:
                    json.dump(self.sessions[session_token], f, indent=2, default=str)
            except Exception as e:
                print(f"Error saving session {session_token}: {e}")
    
    def _load_session(self, session_token: str) -> Optional[Dict]:
        """Load session from disk"""
        session_file = os.path.join(self.session_dir, f"{session_token}.json")
        if os.path.exists(session_file):
            try:
                with open(session_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading session {session_token}: {e}")
        return None
    
    def _delete_session_file(self, session_token: str):
        """Delete session file from disk"""
        session_file = os.path.join(self.session_dir, f"{session_token}.json")
        if os.path.exists(session_file):
            try:
                os.remove(session_file)
            except Exception as e:
                print(f"Error deleting session file {session_token}: {e}")
    
    def _cleanup_loop(self):
        """Background thread to clean up expired sessions"""
        while True:
            threading.Event().wait(300)  # Run every 5 minutes
            self.cleanup_expired_sessions()
    
    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions"""
        expired = []
        
        for session_token, session in self.sessions.items():
            if not self._is_session_valid(session):
                expired.append(session_token)
        
        for session_token in expired:
            self._remove_session(session_token)
        
        return len(expired)
    
    def get_session_stats(self) -> Dict:
        """Get session statistics"""
        return {
            'total_sessions': len(self.sessions),
            'total_users': len(self.user_sessions),
            'sessions_per_user': {
                user_id: len(sessions) 
                for user_id, sessions in self.user_sessions.items()
            },
            'session_timeout': self.session_timeout,
            'max_sessions_per_user': self.max_sessions_per_user
        }


# Singleton instance
session_manager = SessionManager()