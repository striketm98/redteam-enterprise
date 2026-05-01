"""
Session Store - Persistent storage for session data
"""

import json
import os
import pickle
from datetime import datetime
from typing import Dict, Any, Optional, List
import sqlite3


class SessionStore:
    """Persistent storage for session data"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or '/app/sessions/sessions.db'
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for session storage"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                user_data TEXT,
                created_at TEXT,
                last_accessed TEXT,
                expires_at TEXT,
                ip_address TEXT,
                user_agent TEXT,
                data TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        ''')
        
        self.conn.commit()
    
    def save_session(self, session_id: str, session_data: Dict) -> bool:
        """Save session to database"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO sessions 
                (session_id, user_id, user_data, created_at, last_accessed, 
                 expires_at, ip_address, user_agent, data, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                session_data.get('user_id'),
                json.dumps(session_data.get('user_data', {})),
                session_data.get('created_at'),
                session_data.get('last_activity'),
                session_data.get('expires_at'),
                session_data.get('ip_address'),
                session_data.get('user_agent'),
                json.dumps(session_data.get('data', {})),
                1 if session_data.get('is_active', True) else 0
            ))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error saving session {session_id}: {e}")
            return False
    
    def load_session(self, session_id: str) -> Optional[Dict]:
        """Load session from database"""
        try:
            self.cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            row = self.cursor.fetchone()
            
            if row:
                return {
                    'session_id': row[0],
                    'user_id': row[1],
                    'user_data': json.loads(row[2]) if row[2] else {},
                    'created_at': row[3],
                    'last_activity': row[4],
                    'expires_at': row[5],
                    'ip_address': row[6],
                    'user_agent': row[7],
                    'data': json.loads(row[8]) if row[8] else {},
                    'is_active': bool(row[9])
                }
            return None
        except Exception as e:
            print(f"Error loading session {session_id}: {e}")
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session from database"""
        try:
            self.cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting session {session_id}: {e}")
            return False
    
    def delete_user_sessions(self, user_id: str) -> int:
        """Delete all sessions for a user"""
        try:
            self.cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
            count = self.cursor.rowcount
            self.conn.commit()
            return count
        except Exception as e:
            print(f"Error deleting user sessions {user_id}: {e}")
            return 0
    
    def get_user_sessions(self, user_id: str) -> List[Dict]:
        """Get all sessions for a user"""
        try:
            self.cursor.execute('SELECT * FROM sessions WHERE user_id = ? ORDER BY last_accessed DESC', (user_id,))
            rows = self.cursor.fetchall()
            
            sessions = []
            for row in rows:
                sessions.append({
                    'session_id': row[0][:8] + '...',
                    'created_at': row[3],
                    'last_accessed': row[4],
                    'expires_at': row[5],
                    'ip_address': row[6],
                    'user_agent': row[7],
                    'is_active': bool(row[9])
                })
            return sessions
        except Exception as e:
            print(f"Error getting user sessions {user_id}: {e}")
            return []
    
    def update_metadata(self, key: str, value: str) -> bool:
        """Update session metadata"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO session_metadata (key, value, updated_at)
                VALUES (?, ?, ?)
            ''', (key, value, datetime.now().isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error updating metadata {key}: {e}")
            return False
    
    def get_metadata(self, key: str) -> Optional[str]:
        """Get session metadata"""
        try:
            self.cursor.execute('SELECT value FROM session_metadata WHERE key = ?', (key,))
            row = self.cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            print(f"Error getting metadata {key}: {e}")
            return None
    
    def cleanup_expired(self) -> int:
        """Remove expired sessions"""
        try:
            now = datetime.now().isoformat()
            self.cursor.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
            count = self.cursor.rowcount
            self.conn.commit()
            return count
        except Exception as e:
            print(f"Error cleaning expired sessions: {e}")
            return 0
    
    def get_stats(self) -> Dict:
        """Get session store statistics"""
        try:
            self.cursor.execute('SELECT COUNT(*) FROM sessions')
            total = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(DISTINCT user_id) FROM sessions')
            users = self.cursor.fetchone()[0]
            
            self.cursor.execute('''
                SELECT COUNT(*) FROM sessions 
                WHERE datetime(expires_at) > datetime('now')
            ''')
            active = self.cursor.fetchone()[0]
            
            return {
                'total_sessions': total,
                'active_sessions': active,
                'unique_users': users,
                'db_path': self.db_path
            }
        except Exception as e:
            print(f"Error getting stats: {e}")
            return {}
    
    def close(self):
        """Close database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()


# Singleton instance
session_store = SessionStore()