#!/usr/local/bin/python3

"""
Database Manager Module - Enhanced Version
Handles all SQLite database operations with new features:
- IP management (remove/mark safe)
- Port tracking  
- Pagination support
- Search functionality
"""

import os
import sqlite3
from datetime import datetime, timedelta
from .core_utils import log_message, get_db_timestamp, DB_DIR

DB_FILE = os.path.join(DB_DIR, 'abuseipdb.db')

class DatabaseManager:
    """Centralized database operations with enhanced functionality"""
    
    def __init__(self):
        self.db_file = DB_FILE
        self._ensure_database()
    
    def _ensure_database(self):
        """Ensure database exists and is properly initialized"""
        if not os.path.exists(self.db_file):
            log_message("Database not found, initializing...")
            self._initialize_database()
        else:
            # Check for schema updates
            self._update_schema()
    
    def _initialize_database(self):
        """Initialize database with required tables including new columns"""
        try:
            os.makedirs(DB_DIR, mode=0o750, exist_ok=True)
            
            with self.get_connection() as conn:
                c = conn.cursor()
                
                # Create enhanced checked_ips table
                c.execute('''
                CREATE TABLE IF NOT EXISTS checked_ips (
                    ip TEXT PRIMARY KEY,
                    first_seen TEXT,
                    last_checked TEXT,
                    check_count INTEGER,
                    threat_level INTEGER DEFAULT 0,
                    country TEXT DEFAULT 'Unknown',
                    destination_port TEXT DEFAULT ''
                )
                ''')
                
                # Create enhanced threats table
                c.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    ip TEXT PRIMARY KEY,
                    abuse_score INTEGER,
                    reports INTEGER,
                    last_seen TEXT,
                    categories TEXT,
                    country TEXT,
                    threat_level INTEGER DEFAULT 2,
                    marked_safe BOOLEAN DEFAULT 0,
                    marked_safe_date TEXT DEFAULT '',
                    marked_safe_by TEXT DEFAULT '',
                    FOREIGN KEY (ip) REFERENCES checked_ips(ip)
                )
                ''')
                
                # Create stats table
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
                log_message("Enhanced database initialized successfully")
                
        except Exception as e:
            log_message(f"Error initializing database: {str(e)}")
            raise
    
    def _update_schema(self):
        """Update existing database schema with new columns"""
        try:
            with self.get_connection() as conn:
                c = conn.cursor()
                
                # Check and add new columns to checked_ips
                c.execute('PRAGMA table_info(checked_ips)')
                columns = [column[1] for column in c.fetchall()]
                
                if 'country' not in columns:
                    c.execute('ALTER TABLE checked_ips ADD COLUMN country TEXT DEFAULT "Unknown"')
                    log_message("Added country column to checked_ips")
                
                if 'threat_level' not in columns:
                    c.execute('ALTER TABLE checked_ips ADD COLUMN threat_level INTEGER DEFAULT 0')
                    log_message("Added threat_level column to checked_ips")
                
                if 'destination_port' not in columns:
                    c.execute('ALTER TABLE checked_ips ADD COLUMN destination_port TEXT DEFAULT ""')
                    log_message("Added destination_port column to checked_ips")
                
                # Check and add new columns to threats
                c.execute('PRAGMA table_info(threats)')
                threat_columns = [column[1] for column in c.fetchall()]
                
                if 'threat_level' not in threat_columns:
                    c.execute('ALTER TABLE threats ADD COLUMN threat_level INTEGER DEFAULT 2')
                    log_message("Added threat_level column to threats")
                
                if 'marked_safe' not in threat_columns:
                    c.execute('ALTER TABLE threats ADD COLUMN marked_safe BOOLEAN DEFAULT 0')
                    log_message("Added marked_safe column to threats")
                
                if 'marked_safe_date' not in threat_columns:
                    c.execute('ALTER TABLE threats ADD COLUMN marked_safe_date TEXT DEFAULT ""')
                    log_message("Added marked_safe_date column to threats")
                
                if 'marked_safe_by' not in threat_columns:
                    c.execute('ALTER TABLE threats ADD COLUMN marked_safe_by TEXT DEFAULT ""')
                    log_message("Added marked_safe_by column to threats")
                
                conn.commit()
                
        except Exception as e:
            log_message(f"Error updating schema: {str(e)}")
    
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
    
    def update_checked_ip(self, ip, threat_level, country='Unknown', destination_port=''):
        """Update or insert IP into checked_ips table with port info"""
        check_date = get_db_timestamp()
        
        try:
            existing = self.get_checked_ip(ip)
            
            if existing:
                # Update existing record, preserving port info if new port is empty
                # Use dict-style access for sqlite3.Row objects
                existing_port = existing['destination_port'] if 'destination_port' in existing.keys() else ''
                update_port = destination_port if destination_port else existing_port
                self.execute_query(
                    'UPDATE checked_ips SET last_checked = ?, check_count = check_count + 1, threat_level = ?, country = ?, destination_port = ? WHERE ip = ?',
                    (check_date, threat_level, country, update_port, ip)
                )
                log_message(f"Updated checked_ips: {ip} -> threat_level={threat_level}, port={update_port}")
            else:
                self.execute_query(
                    'INSERT INTO checked_ips (ip, first_seen, last_checked, check_count, threat_level, country, destination_port) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (ip, check_date, check_date, 1, threat_level, country, destination_port)
                )
                log_message(f"Inserted checked_ips: {ip} -> threat_level={threat_level}, port={destination_port}")
                
        except Exception as e:
            log_message(f"Error updating checked IP {ip}: {str(e)}")
            raise
    
    def update_threat(self, ip, abuse_score, reports, categories, country):
        """Update or insert threat information"""
        check_date = get_db_timestamp()
        
        try:
            existing = self.get_threat(ip)
            
            if existing:
                # Preserve marked_safe status when updating
                self.execute_query(
                    'UPDATE threats SET abuse_score = ?, reports = ?, last_seen = ?, categories = ?, country = ? WHERE ip = ?',
                    (abuse_score, reports, check_date, categories, country, ip)
                )
                log_message(f"Updated threat: {ip} -> score={abuse_score}")
            else:
                self.execute_query(
                    'INSERT INTO threats (ip, abuse_score, reports, last_seen, categories, country, marked_safe) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (ip, abuse_score, reports, check_date, categories, country, 0)
                )
                log_message(f"Inserted threat: {ip} -> score={abuse_score}")
                
        except Exception as e:
            log_message(f"Error updating threat {ip}: {str(e)}")
            raise
    
    def remove_threat(self, ip):
        """Remove IP from threats table completely"""
        try:
            rowcount = self.execute_query('DELETE FROM threats WHERE ip = ?', (ip,))
            if rowcount > 0:
                log_message(f"Removed {ip} from threats table completely")
                return True
            return False
        except Exception as e:
            log_message(f"Error removing threat {ip}: {str(e)}")
            return False
    
    def mark_ip_safe(self, ip, marked_by='admin'):
        """Mark an IP as safe (keeps in threats table but marked as safe)"""
        try:
            mark_date = get_db_timestamp()
            rowcount = self.execute_query(
                'UPDATE threats SET marked_safe = 1, marked_safe_date = ?, marked_safe_by = ? WHERE ip = ?',
                (mark_date, marked_by, ip)
            )
            if rowcount > 0:
                log_message(f"Marked {ip} as safe by {marked_by}")
                return True
            return False
        except Exception as e:
            log_message(f"Error marking IP {ip} as safe: {str(e)}")
            return False
    
    def unmark_ip_safe(self, ip):
        """Unmark an IP as safe (restore threat status)"""
        try:
            rowcount = self.execute_query(
                'UPDATE threats SET marked_safe = 0, marked_safe_date = "", marked_safe_by = "" WHERE ip = ?',
                (ip,)
            )
            if rowcount > 0:
                log_message(f"Unmarked {ip} as safe - restored threat status")
                return True
            return False
        except Exception as e:
            log_message(f"Error unmarking IP {ip} as safe: {str(e)}")
            return False
    
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
    
    def get_recent_threats(self, limit=20, offset=0, search_ip='', include_marked_safe=True):
        """Get recent threats with pagination and search"""
        try:
            # Build WHERE clause
            where_conditions = []
            params = []
            
            if search_ip:
                where_conditions.append("t.ip LIKE ?")
                params.append(f"%{search_ip}%")
            
            if not include_marked_safe:
                where_conditions.append("(t.marked_safe = 0 OR t.marked_safe IS NULL)")
            
            where_clause = ""
            if where_conditions:
                where_clause = "WHERE " + " AND ".join(where_conditions)
            
            # Get total count
            count_query = f'''
                SELECT COUNT(*) as total
                FROM threats t
                JOIN checked_ips c ON t.ip = c.ip
                {where_clause}
            '''
            total_result = self.execute_query(count_query, params, fetch_one=True)
            total_count = total_result['total'] if total_result else 0
            
            # Get paginated results
            params.extend([limit, offset])
            query = f'''
                SELECT 
                    t.ip, 
                    t.abuse_score, 
                    t.reports, 
                    t.last_seen, 
                    t.country, 
                    t.categories,
                    t.marked_safe,
                    t.marked_safe_date,
                    t.marked_safe_by,
                    c.destination_port
                FROM threats t
                JOIN checked_ips c ON t.ip = c.ip
                {where_clause}
                ORDER BY t.marked_safe ASC, c.last_checked DESC
                LIMIT ? OFFSET ?
            '''
            
            results = self.execute_query(query, params, fetch_all=True)
            
            return {
                'threats': results,
                'total_count': total_count,
                'limit': limit,
                'offset': offset
            }
            
        except Exception as e:
            log_message(f"Error getting recent threats: {str(e)}")
            return {'threats': [], 'total_count': 0, 'limit': limit, 'offset': offset}
    
    def get_all_checked_ips(self, limit=20, offset=0, search_ip=''):
        """Get all checked IPs with pagination and search"""
        try:
            # Build WHERE clause
            where_clause = ""
            params = []
            
            if search_ip:
                where_clause = "WHERE ci.ip LIKE ?"
                params.append(f"%{search_ip}%")
            
            # Get total count
            count_query = f'''
                SELECT COUNT(*) as total
                FROM checked_ips ci
                {where_clause}
            '''
            total_result = self.execute_query(count_query, params, fetch_one=True)
            total_count = total_result['total'] if total_result else 0
            
            # Get paginated results
            params.extend([limit, offset])
            query = f'''
                SELECT 
                    ci.ip,
                    ci.last_checked,
                    ci.threat_level,
                    ci.check_count,
                    ci.country,
                    ci.destination_port,
                    t.abuse_score,
                    t.reports,
                    t.categories,
                    t.marked_safe,
                    t.marked_safe_date,
                    t.marked_safe_by
                FROM checked_ips ci
                LEFT JOIN threats t ON ci.ip = t.ip
                {where_clause}
                ORDER BY ci.last_checked DESC
                LIMIT ? OFFSET ?
            '''
            
            results = self.execute_query(query, params, fetch_all=True)
            
            return {
                'ips': results,
                'total_count': total_count,
                'limit': limit,
                'offset': offset
            }
            
        except Exception as e:
            log_message(f"Error getting all checked IPs: {str(e)}")
            return {'ips': [], 'total_count': 0, 'limit': limit, 'offset': offset}
    
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
    
    def get_threat_ips_for_alias(self, min_threat_level=2, max_hosts=500):
        """Get threat IPs for alias creation (excluding marked safe)"""
        try:
            return self.execute_query('''
                SELECT t.ip, t.abuse_score
                FROM threats t
                JOIN checked_ips ci ON t.ip = ci.ip
                WHERE ci.threat_level >= ? AND (t.marked_safe = 0 OR t.marked_safe IS NULL)
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
            
            # Active threats (excluding marked safe)
            threat_count = self.execute_query('''
                SELECT COUNT(*) as count 
                FROM threats t
                JOIN checked_ips ci ON t.ip = ci.ip
                WHERE ci.threat_level >= ? AND (t.marked_safe = 0 OR t.marked_safe IS NULL)
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
            
            # Marked safe count
            marked_safe_count = self.execute_query(
                'SELECT COUNT(*) as count FROM threats WHERE marked_safe = 1',
                fetch_one=True
            )['count']
            
            # Get stats
            stats = self.get_stats()
            
            return {
                'total_ips': total_ips,
                'total_threats': threat_count,
                'malicious_count': malicious_count,
                'suspicious_count': suspicious_count,
                'marked_safe_count': marked_safe_count,
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
                'marked_safe_count': 0,
                'last_check': 'Error',
                'daily_checks': '0',
                'total_checks': '0'
            }