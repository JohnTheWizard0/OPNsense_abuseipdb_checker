#!/usr/local/bin/python3

"""
Database Manager Module
Handles all SQLite database operations with proper error handling
"""

import os
import sqlite3
from datetime import datetime, timedelta
from .core_utils import log_message, get_db_timestamp, DB_DIR

DB_FILE = os.path.join(DB_DIR, 'abuseipdb.db')

class DatabaseManager:
    """Centralized database operations with connection management"""
    
    def __init__(self):
        self.db_file = DB_FILE
        self._ensure_database()
    
    def _ensure_database(self):
        """Ensure database exists and is properly initialized"""
        if not os.path.exists(self.db_file):
            log_message("Database not found, initializing...")
            self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database with required tables"""
        try:
            os.makedirs(DB_DIR, mode=0o750, exist_ok=True)
            
            with self.get_connection() as conn:
                c = conn.cursor()
                
                # Create tables with migration support
                c.execute('''
                CREATE TABLE IF NOT EXISTS checked_ips (
                    ip TEXT PRIMARY KEY,
                    first_seen TEXT,
                    last_checked TEXT,
                    check_count INTEGER,
                    threat_level INTEGER DEFAULT 0,
                    country TEXT DEFAULT 'Unknown'
                )
                ''')
                
                c.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    ip TEXT PRIMARY KEY,
                    abuse_score INTEGER,
                    reports INTEGER,
                    last_seen TEXT,
                    categories TEXT,
                    country TEXT,
                    threat_level INTEGER DEFAULT 2,
                    FOREIGN KEY (ip) REFERENCES checked_ips(ip)
                )
                ''')
                
                c.execute('''
                CREATE TABLE IF NOT EXISTS stats (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
                ''')
                
                # Initialize stats
                c.execute('INSERT OR IGNORE INTO stats (key, value) VALUES (?, ?)', ('last_check', 'Never'))
                c.execute('INSERT OR IGNORE INTO stats (key, value) VALUES (?, ?)', ('daily_checks', '0'))
                c.execute('INSERT OR IGNORE INTO stats (key, value) VALUES (?, ?)', ('total_checks', '0'))
                c.execute('INSERT OR IGNORE INTO stats (key, value) VALUES (?, ?)', ('last_reset', ''))
                
                conn.commit()
                log_message("Database initialized successfully")
                
        except Exception as e:
            log_message(f"Error initializing database: {str(e)}")
            raise
    
    def get_connection(self):
        """Get database connection with row factory"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        return conn
    
    def execute_query(self, query, params=None, fetch_one=False, fetch_all=False):
        """Execute query with proper error handling"""
        try:
            with self.get_connection() as conn:
                c = conn.cursor()
                if params:
                    c.execute(query, params)
                else:
                    c.execute(query)
                
                if fetch_one:
                    return c.fetchone()
                elif fetch_all:
                    return c.fetchall()
                else:
                    conn.commit()
                    return c.rowcount
        except Exception as e:
            log_message(f"Database query error: {str(e)}")
            raise
    
    def update_checked_ip(self, ip, threat_level, country='Unknown'):
        """Update or insert IP into checked_ips table"""
        check_date = get_db_timestamp()
        
        try:
            existing = self.get_checked_ip(ip)
            
            if existing:
                self.execute_query(
                    'UPDATE checked_ips SET last_checked = ?, check_count = check_count + 1, threat_level = ?, country = ? WHERE ip = ?',
                    (check_date, threat_level, country, ip)
                )
                log_message(f"Updated checked_ips: {ip} -> threat_level={threat_level}")
            else:
                self.execute_query(
                    'INSERT INTO checked_ips (ip, first_seen, last_checked, check_count, threat_level, country) VALUES (?, ?, ?, ?, ?, ?)',
                    (ip, check_date, check_date, 1, threat_level, country)
                )
                log_message(f"Inserted checked_ips: {ip} -> threat_level={threat_level}")
                
        except Exception as e:
            log_message(f"Error updating checked IP {ip}: {str(e)}")
            raise
    
    def update_threat(self, ip, abuse_score, reports, categories, country):
        """Update or insert threat information"""
        check_date = get_db_timestamp()
        
        try:
            existing = self.get_threat(ip)
            
            if existing:
                self.execute_query(
                    'UPDATE threats SET abuse_score = ?, reports = ?, last_seen = ?, categories = ?, country = ? WHERE ip = ?',
                    (abuse_score, reports, check_date, categories, country, ip)
                )
                log_message(f"Updated threat: {ip} -> score={abuse_score}")
            else:
                self.execute_query(
                    'INSERT INTO threats (ip, abuse_score, reports, last_seen, categories, country) VALUES (?, ?, ?, ?, ?, ?)',
                    (ip, abuse_score, reports, check_date, categories, country)
                )
                log_message(f"Inserted threat: {ip} -> score={abuse_score}")
                
        except Exception as e:
            log_message(f"Error updating threat {ip}: {str(e)}")
            raise
    
    def remove_threat(self, ip):
        """Remove IP from threats table (no longer a threat)"""
        try:
            rowcount = self.execute_query('DELETE FROM threats WHERE ip = ?', (ip,))
            if rowcount > 0:
                log_message(f"Removed {ip} from threats table (no longer a threat)")
        except Exception as e:
            log_message(f"Error removing threat {ip}: {str(e)}")
    
    def get_checked_ip(self, ip):
        """Get checked IP record"""
        return self.execute_query(
            'SELECT * FROM checked_ips WHERE ip = ?', 
            (ip,), 
            fetch_one=True
        )
    
    def get_threat(self, ip):
        """Get threat record"""
        return self.execute_query(
            'SELECT * FROM threats WHERE ip = ?', 
            (ip,), 
            fetch_one=True
        )
    
    def get_ips_needing_check(self, check_frequency_days):
        """Get IPs that need to be checked based on frequency"""
        cutoff_date = (datetime.now() - timedelta(days=check_frequency_days)).strftime('%Y-%m-%d %H:%M:%S')
        
        return self.execute_query(
            'SELECT ip FROM checked_ips WHERE last_checked < ?',
            (cutoff_date,),
            fetch_all=True
        )
    
    def get_stats(self):
        """Get all statistics"""
        try:
            stats_rows = self.execute_query('SELECT key, value FROM stats', fetch_all=True)
            stats = {}
            for row in stats_rows:
                stats[row['key']] = row['value']
            return stats
        except Exception as e:
            log_message(f"Error getting stats: {str(e)}")
            return {}
    
    def update_stat(self, key, value):
        """Update a single statistic"""
        try:
            self.execute_query(
                'INSERT OR REPLACE INTO stats (key, value) VALUES (?, ?)',
                (key, str(value))
            )
        except Exception as e:
            log_message(f"Error updating stat {key}: {str(e)}")
    
    def get_stat(self, key, default=None):
        """Get a single statistic"""
        try:
            result = self.execute_query(
                'SELECT value FROM stats WHERE key = ?',
                (key,),
                fetch_one=True
            )
            return result['value'] if result else default
        except Exception as e:
            log_message(f"Error getting stat {key}: {str(e)}")
            return default
    
    def reset_daily_checks_if_needed(self):
        """Reset daily checks count if it's a new day"""
        try:
            last_reset = self.get_stat('last_reset')
            today = datetime.now().strftime('%Y-%m-%d')
            
            if last_reset != today:
                self.update_stat('daily_checks', '0')
                self.update_stat('last_reset', today)
                log_message("Daily checks counter reset for new day")
        except Exception as e:
            log_message(f"Error resetting daily checks: {str(e)}")
    
    def get_recent_threats(self, limit=20):
        """Get recent threats with full details"""
        try:
            return self.execute_query('''
                SELECT t.ip, t.abuse_score, t.reports, t.last_seen, t.country, t.categories
                FROM threats t
                JOIN checked_ips c ON t.ip = c.ip
                ORDER BY c.last_checked DESC
                LIMIT ?
            ''', (limit,), fetch_all=True)
        except Exception as e:
            log_message(f"Error getting recent threats: {str(e)}")
            return []
    
    def get_all_checked_ips(self, limit=100):
        """Get all checked IPs with threat information"""
        try:
            return self.execute_query('''
                SELECT 
                    ci.ip,
                    ci.last_checked,
                    ci.threat_level,
                    ci.check_count,
                    ci.country,
                    t.abuse_score,
                    t.reports,
                    t.categories
                FROM checked_ips ci
                LEFT JOIN threats t ON ci.ip = t.ip
                ORDER BY ci.last_checked DESC
                LIMIT ?
            ''', (limit,), fetch_all=True)
        except Exception as e:
            log_message(f"Error getting all checked IPs: {str(e)}")
            return []
    
    def get_threat_ips_for_alias(self, min_threat_level=2, max_hosts=500):
        """Get threat IPs for alias creation"""
        try:
            return self.execute_query('''
                SELECT t.ip, t.abuse_score
                FROM threats t
                JOIN checked_ips ci ON t.ip = ci.ip
                WHERE ci.threat_level >= ?
                ORDER BY 
                    t.abuse_score DESC,
                    ci.last_checked DESC
                LIMIT ?
            ''', (min_threat_level, max_hosts), fetch_all=True)
        except Exception as e:
            log_message(f"Error getting threat IPs for alias: {str(e)}")
            return []
    
    def get_statistics_summary(self, config=None):
        """Get comprehensive statistics summary"""
        try:
            # Basic counts
            total_ips = self.execute_query('SELECT COUNT(*) as count FROM checked_ips', fetch_one=True)['count']
            
            # Threat counts based on config
            if config and config.get('alias_include_suspicious', False):
                min_threat_level = 1
            else:
                min_threat_level = 2
            
            threat_count = self.execute_query('''
                SELECT COUNT(*) as count 
                FROM threats t
                JOIN checked_ips ci ON t.ip = ci.ip
                WHERE ci.threat_level >= ?
            ''', (min_threat_level,), fetch_one=True)['count']
            
            # Breakdown counts
            suspicious_count = self.execute_query(
                'SELECT COUNT(*) as count FROM checked_ips WHERE threat_level = 1',
                fetch_one=True
            )['count']
            
            malicious_count = self.execute_query(
                'SELECT COUNT(*) as count FROM checked_ips WHERE threat_level = 2',
                fetch_one=True
            )['count']
            
            # Get stats
            stats = self.get_stats()
            
            return {
                'total_ips': total_ips,
                'total_threats': threat_count,
                'malicious_count': malicious_count,
                'suspicious_count': suspicious_count,
                'last_check': stats.get('last_check', 'Never'),
                'daily_checks': stats.get('daily_checks', '0'),
                'total_checks': stats.get('total_checks', '0')
            }
            
        except Exception as e:
            log_message(f"Error getting statistics summary: {str(e)}")
            return {
                'total_ips': 0,
                'total_threats': 0,
                'malicious_count': 0,
                'suspicious_count': 0,
                'last_check': 'Error',
                'daily_checks': '0',
                'total_checks': '0'
            }