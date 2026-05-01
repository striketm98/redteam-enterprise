"""
Session Cleanup - Automated cleanup of expired and stale sessions
"""

import threading
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List
import os

logger = logging.getLogger(__name__)


class SessionCleanup:
    """Automated cleanup of expired sessions"""
    
    def __init__(self, session_manager=None, session_store=None):
        self.session_manager = session_manager
        self.session_store = session_store
        self.cleanup_interval = 300  # 5 minutes
        self.max_session_age = 86400  # 24 hours
        self.is_running = False
        self.cleanup_thread = None
        
        # Statistics
        self.stats = {
            'total_cleanups': 0,
            'sessions_cleaned': 0,
            'last_cleanup': None
        }
    
    def start(self):
        """Start the cleanup service"""
        if self.is_running:
            return
        
        self.is_running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        logger.info("Session cleanup service started")
    
    def stop(self):
        """Stop the cleanup service"""
        self.is_running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        logger.info("Session cleanup service stopped")
    
    def _cleanup_loop(self):
        """Main cleanup loop"""
        while self.is_running:
            try:
                self.run_cleanup()
            except Exception as e:
                logger.error(f"Error during session cleanup: {e}")
            
            # Sleep until next cleanup
            time.sleep(self.cleanup_interval)
    
    def run_cleanup(self) -> Dict:
        """Run cleanup operation"""
        start_time = datetime.now()
        cleaned_count = 0
        
        # Cleanup from session manager
        if self.session_manager:
            cleaned_count += self.session_manager.cleanup_expired_sessions()
        
        # Cleanup from session store
        if self.session_store:
            cleaned_count += self.session_store.cleanup_expired()
        
        # Cleanup session files
        cleaned_count += self._cleanup_session_files()
        
        # Update statistics
        self.stats['total_cleanups'] += 1
        self.stats['sessions_cleaned'] += cleaned_count
        self.stats['last_cleanup'] = datetime.now().isoformat()
        
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.info(f"Session cleanup completed: {cleaned_count} sessions removed in {duration:.2f}s")
        
        return {
            'sessions_cleaned': cleaned_count,
            'duration_seconds': duration,
            'timestamp': datetime.now().isoformat()
        }
    
    def _cleanup_session_files(self) -> int:
        """Clean up orphaned session files"""
        cleaned = 0
        session_dir = '/app/sessions/data'
        
        if not os.path.exists(session_dir):
            return 0
        
        now = datetime.now()
        
        for filename in os.listdir(session_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(session_dir, filename)
                
                # Check file age
                file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                file_age = (now - file_mtime).total_seconds()
                
                # Remove files older than max_session_age
                if file_age > self.max_session_age:
                    try:
                        os.remove(filepath)
                        cleaned += 1
                        logger.debug(f"Removed orphaned session file: {filename}")
                    except Exception as e:
                        logger.error(f"Failed to remove session file {filename}: {e}")
        
        return cleaned
    
    def cleanup_user_sessions(self, user_id: str) -> int:
        """Clean up all sessions for a specific user"""
        cleaned = 0
        
        if self.session_manager:
            cleaned += self.session_manager.delete_user_sessions(user_id)
        
        if self.session_store:
            cleaned += self.session_store.delete_user_sessions(user_id)
        
        logger.info(f"Cleaned {cleaned} sessions for user {user_id}")
        return cleaned
    
    def get_cleanup_stats(self) -> Dict:
        """Get cleanup statistics"""
        stats = self.stats.copy()
        
        # Add current state
        if self.session_manager:
            stats['current_sessions'] = self.session_manager.get_active_sessions_count()
        
        if self.session_store:
            store_stats = self.session_store.get_stats()
            stats['db_sessions'] = store_stats.get('total_sessions', 0)
        
        stats['is_running'] = self.is_running
        stats['cleanup_interval_seconds'] = self.cleanup_interval
        stats['max_session_age_hours'] = self.max_session_age / 3600
        
        return stats
    
    def set_cleanup_interval(self, seconds: int):
        """Set cleanup interval"""
        self.cleanup_interval = max(60, seconds)  # Minimum 1 minute
        logger.info(f"Cleanup interval set to {self.cleanup_interval} seconds")
    
    def set_max_session_age(self, seconds: int):
        """Set maximum session age"""
        self.max_session_age = max(3600, seconds)  # Minimum 1 hour
        logger.info(f"Max session age set to {self.max_session_age} seconds")
    
    def force_cleanup(self) -> Dict:
        """Force an immediate cleanup"""
        logger.info("Forcing immediate session cleanup")
        return self.run_cleanup()


# Singleton instance
session_cleanup = SessionCleanup()