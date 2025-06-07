#!/usr/local/bin/python3

"""
Core Utilities Module
Handles timezone, logging, directories, and classification utilities
"""

import os
import sys
import subprocess
from datetime import datetime, timedelta, timezone

# Constants
DB_DIR = '/var/db/abuseipdbchecker'
LOG_DIR = '/var/log/abuseipdbchecker'
CONFIG_DIR = '/usr/local/etc/abuseipdbchecker'
LOG_FILE = os.path.join(LOG_DIR, 'abuseipdb.log')

class TimezoneManager:
    """Handles all timezone operations consistently"""
    
    def __init__(self):
        self.local_tz = self._get_system_timezone()
    
    def _get_system_timezone(self):
        """Get the system's local timezone safely"""
        try:
            local_dt = datetime.now().astimezone()
            return local_dt.tzinfo
        except Exception:
            try:
                import time
                if time.daylight:
                    offset_seconds = -time.altzone
                else:
                    offset_seconds = -time.timezone
                
                offset_hours = offset_seconds // 3600
                offset_minutes = (abs(offset_seconds) % 3600) // 60
                
                return timezone(timedelta(hours=offset_hours, minutes=offset_minutes))
            except Exception:
                return timezone.utc
    
    def get_local_time(self):
        """Get current time in system's local timezone"""
        return datetime.now(self.local_tz)
    
    def format_timestamp(self, dt=None):
        """Format timestamp in local timezone"""
        if dt is None:
            dt = self.get_local_time()
        elif isinstance(dt, str):
            try:
                if dt.endswith('Z'):
                    dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
                elif '+' in dt or dt.count('-') > 2:
                    dt = datetime.fromisoformat(dt)
                else:
                    dt = datetime.fromisoformat(dt)
                    dt = dt.replace(tzinfo=self.local_tz)
                dt = dt.astimezone(self.local_tz)
            except Exception:
                return dt
        elif dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc).astimezone(self.local_tz)
        elif dt.tzinfo != self.local_tz:
            dt = dt.astimezone(self.local_tz)
        
        return dt.strftime('%Y-%m-%d %H:%M:%S %Z')
    
    def get_db_timestamp(self):
        """Get timestamp for database storage"""
        return self.get_local_time().strftime('%Y-%m-%d %H:%M:%S')

# Global timezone manager instance
_tz_manager = TimezoneManager()

# Export timezone functions at module level
get_local_time = _tz_manager.get_local_time
format_timestamp = _tz_manager.format_timestamp
get_db_timestamp = _tz_manager.get_db_timestamp

class DirectoryManager:
    """Handles directory creation and permissions"""
    
    @staticmethod
    def ensure_directories():
        """Ensure all required directories exist with correct permissions"""
        dirs = [
            (DB_DIR, 0o755),
            (LOG_DIR, 0o755),
            (CONFIG_DIR, 0o755)
        ]
        
        for directory, mode in dirs:
            if not os.path.exists(directory):
                try:
                    os.makedirs(directory, mode=mode)
                    print(f"Created directory: {directory}", file=sys.stderr)
                    
                    try:
                        subprocess.run(['chown', '-R', 'www:www', directory], check=False)
                    except Exception as e:
                        print(f"Note: Could not set ownership for {directory}: {str(e)}", file=sys.stderr)
                except Exception as e:
                    print(f"Error creating directory {directory}: {str(e)}", file=sys.stderr)

class Logger:
    """Centralized logging with proper error handling"""
    
    @staticmethod
    def log_message(message):
        """Log a message with proper timezone and error handling"""
        try:
            if not os.path.exists(LOG_DIR):
                try:
                    os.makedirs(LOG_DIR, mode=0o755)
                    try:
                        subprocess.run(['chown', '-R', 'www:www', LOG_DIR], check=False)
                    except Exception:
                        pass
                except Exception as e:
                    print(f"Error creating log directory: {str(e)}", file=sys.stderr)
                    return
            
            # Skip repetitive startup messages
            if "Script started successfully" in message and os.path.exists(LOG_FILE):
                return
                
            timestamp = format_timestamp()
            with open(LOG_FILE, 'a') as f:
                f.write(f"[{timestamp}] {message}\n")
            
            try:
                os.chmod(LOG_FILE, 0o666)
                subprocess.run(['chown', 'www:www', LOG_FILE], check=False)
            except Exception:
                pass
        
        except Exception as e:
            print(f"Error writing to log: {str(e)}", file=sys.stderr)
            try:
                import syslog
                syslog.openlog("abuseipdbchecker")
                syslog.syslog(syslog.LOG_ERR, f"Error writing to log file: {str(e)}")
                syslog.syslog(syslog.LOG_NOTICE, f"Original message: {message}")
                syslog.closelog()
            except Exception:
                pass
    
    @staticmethod
    def system_log(message, priority=5):
        """Log to system log as fallback"""
        try:
            import syslog
            syslog.openlog("abuseipdbchecker")
            syslog.syslog(priority, message)
            syslog.closelog()
        except Exception as e:
            print(f"Error writing to syslog: {str(e)}", file=sys.stderr)

class ThreatClassifier:
    """Handles threat level classification logic"""
    
    @staticmethod
    def classify_threat_level(abuse_score, config=None):
        """Classify threat level based on abuse score and configuration
        Returns: 0 = Safe, 1 = Suspicious, 2 = Malicious
        """
        if config is None:
            suspicious_threshold = 40
            malicious_threshold = 70
        else:
            suspicious_threshold = config.get('suspicious_threshold', 40)
            malicious_threshold = config.get('malicious_threshold', 70)
        
        if abuse_score < suspicious_threshold:
            return 0  # Safe
        elif abuse_score < malicious_threshold:
            return 1  # Suspicious
        else:
            return 2  # Malicious
    
    @staticmethod
    def get_threat_level_text(threat_level):
        """Convert threat level to human-readable text"""
        levels = {0: 'Safe', 1: 'Suspicious', 2: 'Malicious'}
        return levels.get(threat_level, 'Unknown')

# Export functions at module level for backward compatibility
ensure_directories = DirectoryManager.ensure_directories
log_message = Logger.log_message
system_log = Logger.system_log
classify_threat_level = ThreatClassifier.classify_threat_level
get_threat_level_text = ThreatClassifier.get_threat_level_text

def log_timezone_info():
    """Log timezone information for debugging"""
    try:
        import time
        local_time = get_local_time()
        log_message(f"System timezone: {_tz_manager.local_tz}")
        log_message(f"Current local time: {format_timestamp()}")
        log_message(f"UTC offset: {local_time.strftime('%z')}")
        log_message(f"Timezone name: {local_time.strftime('%Z')}")
        if hasattr(time, 'tzname'):
            log_message(f"System tzname: {time.tzname}")
    except Exception as e:
        log_message(f"Error logging timezone info: {str(e)}")
