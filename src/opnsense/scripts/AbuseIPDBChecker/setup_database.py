#!/usr/local/bin/python3

"""
    Copyright (c) 2023 Your Name
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    --------------------------------------------------------------------------------------
    Initialize the SQLite database for AbuseIPDBChecker
"""
import os
import sqlite3
import json

DB_DIR = '/var/db/abuseipdbchecker'
DB_FILE = os.path.join(DB_DIR, 'abuseipdb.db')

def ensure_dir_exists():
    """Ensure database directory exists"""
    if not os.path.exists(DB_DIR):
        try:
            os.makedirs(DB_DIR, mode=0o750)
        except OSError as e:
            return {'status': 'failed', 'message': f'Error creating database directory: {str(e)}'}
    return {'status': 'ok'}

def setup_database():
    """Initialize the SQLite database with migration support"""
    try:
        # Ensure directory exists
        dir_result = ensure_dir_exists()
        if dir_result['status'] != 'ok':
            return dir_result

        # Create database file
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        # Create tables with new schema
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

        # Migration: Add country column if missing
        c.execute('PRAGMA table_info(checked_ips)')
        columns = [column[1] for column in c.fetchall()]
        if 'country' not in columns:
            c.execute('ALTER TABLE checked_ips ADD COLUMN country TEXT DEFAULT "Unknown"')
        
        if 'threat_level' not in columns:
            if 'is_threat' in columns:
                # Migrate existing data using old threshold logic
                c.execute('ALTER TABLE checked_ips ADD COLUMN threat_level INTEGER DEFAULT 0')
                c.execute('UPDATE checked_ips SET threat_level = 2 WHERE is_threat = 1')  # Old threats become malicious
                c.execute('UPDATE checked_ips SET threat_level = 0 WHERE is_threat = 0')  # Old safe remain safe
            else:
                # New installation
                c.execute('ALTER TABLE checked_ips ADD COLUMN threat_level INTEGER DEFAULT 0')

        # Rest of table creation...
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

        # Add threat_level to threats table if missing
        c.execute('PRAGMA table_info(threats)')
        threat_columns = [column[1] for column in c.fetchall()]
        if 'threat_level' not in threat_columns:
            c.execute('ALTER TABLE threats ADD COLUMN threat_level INTEGER DEFAULT 2')

        # Create stats table (unchanged)
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
        conn.close()

        # Set correct permissions
        os.chmod(DB_FILE, 0o640)

        return {'status': 'ok', 'message': 'Database initialized successfully with three-tier classification'}
    
    except Exception as e:
        return {'status': 'failed', 'message': f'Error initializing database: {str(e)}'}

if __name__ == '__main__':
    result = setup_database()
    print(json.dumps(result))