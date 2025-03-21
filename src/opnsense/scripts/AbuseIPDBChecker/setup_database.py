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
    """Initialize the SQLite database"""
    try:
        # Ensure directory exists
        dir_result = ensure_dir_exists()
        if dir_result['status'] != 'ok':
            return dir_result

        # Create database file
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        # Create tables
        c.execute('''
        CREATE TABLE IF NOT EXISTS checked_ips (
            ip TEXT PRIMARY KEY,
            first_seen TEXT,
            last_checked TEXT,
            check_count INTEGER,
            is_threat INTEGER DEFAULT 0
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
        conn.close()

        # Set correct permissions
        os.chmod(DB_FILE, 0o640)

        return {'status': 'ok', 'message': 'Database initialized successfully'}
    
    except Exception as e:
        return {'status': 'failed', 'message': f'Error initializing database: {str(e)}'}

if __name__ == '__main__':
    result = setup_database()
    print(json.dumps(result))