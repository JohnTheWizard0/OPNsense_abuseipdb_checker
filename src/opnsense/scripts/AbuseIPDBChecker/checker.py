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
    AbuseIPDB Checker Script - Checks IPs against AbuseIPDB
"""
import os
import sys
import time
import json
import sqlite3
import ipaddress
import re
import requests
import smtplib
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from configparser import ConfigParser

# Constants
DB_DIR = '/var/db/abuseipdbchecker'
DB_FILE = os.path.join(DB_DIR, 'abuseipdb.db')
CONFIG_FILE = '/usr/local/etc/abuseipdbchecker/abuseipdbchecker.conf'

# Command modes
MODE_CHECK = 'check'
MODE_STATS = 'stats'
MODE_THREATS = 'threats'

def read_config():
    """Read configuration from OPNsense config file"""
    config = {
        'enabled': False,
        'log_file': '/var/log/filter.log',
        'check_frequency': 7,
        'abuse_score_threshold': 80,
        'daily_check_limit': 100,
        'ignore_blocked_connections': True,
        'lan_subnets': ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
        'ignore_protocols': ['icmp', 'igmp'],
        'api_key': '',
        'api_endpoint': 'https://api.abuseipdb.com/api/v2/check',
        'max_age': 90,
        'email_enabled': False,
        'smtp_server': '',
        'smtp_port': 587,
        'smtp_username': '',
        'smtp_password': '',
        'from_address': '',
        'to_address': '',
        'use_tls': True
    }
    
    # Make sure config directory exists
    config_dir = os.path.dirname(CONFIG_FILE)
    if not os.path.exists(config_dir):
        try:
            os.makedirs(config_dir, mode=0o755)
        except OSError as e:
            print(f"Error creating config directory: {str(e)}", file=sys.stderr)
    
    if os.path.exists(CONFIG_FILE):
        try:
            cp = ConfigParser()
            cp.read(CONFIG_FILE)
            
            if cp.has_section('general'):
                if cp.has_option('general', 'Enabled'):
                    config['enabled'] = cp.get('general', 'Enabled') == '1'
                if cp.has_option('general', 'LogFile'):
                    config['log_file'] = cp.get('general', 'LogFile')
                if cp.has_option('general', 'CheckFrequency'):
                    config['check_frequency'] = int(cp.get('general', 'CheckFrequency'))
                if cp.has_option('general', 'AbuseScoreThreshold'):
                    config['abuse_score_threshold'] = int(cp.get('general', 'AbuseScoreThreshold'))
                if cp.has_option('general', 'DailyCheckLimit'):
                    config['daily_check_limit'] = int(cp.get('general', 'DailyCheckLimit'))
                if cp.has_option('general', 'IgnoreBlockedConnections'):
                    config['ignore_blocked_connections'] = cp.get('general', 'IgnoreBlockedConnections') == '1'
            
            if cp.has_section('network'):
                if cp.has_option('network', 'LanSubnets'):
                    config['lan_subnets'] = [subnet.strip() for subnet in cp.get('network', 'LanSubnets').split(',')]
                if cp.has_option('network', 'IgnoreProtocols'):
                    config['ignore_protocols'] = [proto.strip() for proto in cp.get('network', 'IgnoreProtocols').split(',')]
            
            if cp.has_section('api'):
                if cp.has_option('api', 'Key'):
                    config['api_key'] = cp.get('api', 'Key')
                if cp.has_option('api', 'Endpoint'):
                    config['api_endpoint'] = cp.get('api', 'Endpoint')
                if cp.has_option('api', 'MaxAge'):
                    config['max_age'] = int(cp.get('api', 'MaxAge'))
            
            if cp.has_section('email'):
                if cp.has_option('email', 'Enabled'):
                    config['email_enabled'] = cp.get('email', 'Enabled') == '1'
                if cp.has_option('email', 'SmtpServer'):
                    config['smtp_server'] = cp.get('email', 'SmtpServer')
                if cp.has_option('email', 'SmtpPort'):
                    config['smtp_port'] = int(cp.get('email', 'SmtpPort'))
                if cp.has_option('email', 'SmtpUsername'):
                    config['smtp_username'] = cp.get('email', 'SmtpUsername')
                if cp.has_option('email', 'SmtpPassword'):
                    config['smtp_password'] = cp.get('email', 'SmtpPassword')
                if cp.has_option('email', 'FromAddress'):
                    config['from_address'] = cp.get('email', 'FromAddress')
                if cp.has_option('email', 'ToAddress'):
                    config['to_address'] = cp.get('email', 'ToAddress')
                if cp.has_option('email', 'UseTLS'):
                    config['use_tls'] = cp.get('email', 'UseTLS') == '1'
        except Exception as e:
            print(f"Error reading config: {str(e)}", file=sys.stderr)
    
    return config

def is_ip_in_networks(ip, networks):
    """Check if IP is in any of the specified networks"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in networks:
            try:
                if ip_obj in ipaddress.ip_network(network):
                    return True
            except ValueError:
                continue
        return False
    except ValueError:
        return False

def parse_log_for_ips(config):
    """Parse firewall log for external IPs connecting to LAN"""
    external_ips = set()
    
    if not os.path.exists(config['log_file']):
        return external_ips
    
    # Convert LAN subnets to proper network objects
    lan_networks = []
    for subnet in config['lan_subnets']:
        try:
            lan_networks.append(ipaddress.ip_network(subnet))
        except ValueError:
            continue
    
    # Regular expression for IPv4 addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    # Read and parse log file
    with open(config['log_file'], 'r') as f:
        for line in f:
            # Skip lines with ignored protocols
            if any(proto in line.lower() for proto in config['ignore_protocols']):
                continue
                
            # Skip blocked connections if configured
            if config['ignore_blocked_connections'] and 'block' in line.lower():
                continue
                
            # Find all IPs in the line
            matches = ip_pattern.findall(line)
            for ip in matches:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    
                    # Skip private IPs and IPs in LAN subnets
                    if ip_obj.is_private or any(ip_obj in network for network in lan_networks):
                        continue
                        
                    external_ips.add(ip)
                except ValueError:
                    continue
    
    return external_ips

def check_ip_abuseipdb(ip, config):
    """Check an IP against AbuseIPDB API"""
    if not config['api_key']:
        return None
        
    headers = {
        'Key': config['api_key'],
        'Accept': 'application/json'
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': config['max_age']
    }
    
    try:
        response = requests.get(
            config['api_endpoint'], 
            headers=headers, 
            params=params
        )
        
        if response.status_code == 200:
            return response.json().get('data', {})
        else:
            print(f"API error: {response.status_code} - {response.text}", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error checking IP {ip}: {str(e)}", file=sys.stderr)
        return None

def send_email_notification(threat_ip, report, config):
    """Send email notification about detected threat"""
    if not config['email_enabled'] or not config['smtp_server'] or not config['from_address'] or not config['to_address']:
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = config['from_address']
        msg['To'] = config['to_address']
        msg['Subject'] = f"AbuseIPDB Alert: Malicious IP {threat_ip} detected"
        
        body = f"""
        <html>
        <body>
            <h2>AbuseIPDB Threat Alert</h2>
            <p>A potentially malicious IP has been detected connecting to your network:</p>
            <table border="1" cellpadding="5">
                <tr>
                    <th>IP Address</th>
                    <td>{threat_ip}</td>
                </tr>
                <tr>
                    <th>Abuse Confidence Score</th>
                    <td>{report.get('abuseConfidenceScore', 'N/A')}%</td>
                </tr>
                <tr>
                    <th>Reports Count</th>
                    <td>{report.get('totalReports', 'N/A')}</td>
                </tr>
                <tr>
                    <th>Last Reported</th>
                    <td>{report.get('lastReportedAt', 'N/A')}</td>
                </tr>
                <tr>
                    <th>Country</th>
                    <td>{report.get('countryCode', 'N/A')}</td>
                </tr>
            </table>
            <p>Details: <a href="https://www.abuseipdb.com/check/{threat_ip}">View on AbuseIPDB</a></p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        if config['use_tls']:
            server.starttls()
        
        if config['smtp_username'] and config['smtp_password']:
            server.login(config['smtp_username'], config['smtp_password'])
        
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}", file=sys.stderr)
        return False

def update_db_stats(conn, key, value):
    """Update a value in the stats table"""
    try:
        c = conn.cursor()
        c.execute('UPDATE stats SET value = ? WHERE key = ?', (value, key))
        conn.commit()
    except Exception as e:
        print(f"Error updating stats: {str(e)}", file=sys.stderr)

def get_db_stats(conn, key):
    """Get a value from the stats table"""
    try:
        c = conn.cursor()
        c.execute('SELECT value FROM stats WHERE key = ?', (key,))
        result = c.fetchone()
        if result:
            return result[0]
        return None
    except Exception as e:
        print(f"Error getting stats: {str(e)}", file=sys.stderr)
        return None

def reset_daily_checks_if_needed(conn):
    """Reset daily checks count if it's a new day"""
    try:
        c = conn.cursor()
        last_reset = get_db_stats(conn, 'last_reset')
        today = datetime.now().strftime('%Y-%m-%d')
        
        if last_reset != today:
            c.execute('UPDATE stats SET value = ? WHERE key = ?', ('0', 'daily_checks'))
            c.execute('UPDATE stats SET value = ? WHERE key = ?', (today, 'last_reset'))
            conn.commit()
    except Exception as e:
        print(f"Error resetting daily checks: {str(e)}", file=sys.stderr)

def run_checker(config):
    """Main function to run the checker"""
    if not config['enabled']:
        return {'status': 'disabled', 'message': 'AbuseIPDBChecker is disabled'}
    
    # Make sure DB exists
    if not os.path.exists(DB_FILE):
        return {'status': 'error', 'message': 'Database not initialized. Please run setup_database.py first.'}
    
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    
    try:
        # Reset daily checks if it's a new day
        reset_daily_checks_if_needed(conn)
        
        # Get external IPs from log
        external_ips = parse_log_for_ips(config)
        
        if not external_ips:
            update_db_stats(conn, 'last_check', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            return {'status': 'ok', 'message': 'No external IPs found to check'}
        
        # Get current stats
        daily_checks = int(get_db_stats(conn, 'daily_checks') or '0')
        daily_limit = config['daily_check_limit']
        
        if daily_checks >= daily_limit:
            return {'status': 'limited', 'message': f'Daily API check limit reached ({daily_checks}/{daily_limit})'}
        
        # Check each IP
        c = conn.cursor()
        now = datetime.now()
        check_date = now.strftime('%Y-%m-%d %H:%M:%S')
        
        threats_detected = 0
        ips_checked = 0
        
        for ip in external_ips:
            # Check if we've reached the daily limit
            if daily_checks >= daily_limit:
                break
            
            # Check if this IP is already in the database
            c.execute('SELECT * FROM checked_ips WHERE ip = ?', (ip,))
            existing = c.fetchone()
            
            # If IP exists and was checked recently, skip it
            if existing and datetime.strptime(existing['last_checked'], '%Y-%m-%d %H:%M:%S') > (now - timedelta(days=config['check_frequency'])):
                continue
            
            # Check IP against AbuseIPDB
            report = check_ip_abuseipdb(ip, config)
            
            if report is not None:
                abuse_score = report.get('abuseConfidenceScore', 0)
                is_threat = abuse_score >= config['abuse_score_threshold']
                
                # Update or insert into checked_ips
                if existing:
                    c.execute(
                        'UPDATE checked_ips SET last_checked = ?, check_count = check_count + 1, is_threat = ? WHERE ip = ?',
                        (check_date, 1 if is_threat else 0, ip)
                    )
                else:
                    c.execute(
                        'INSERT INTO checked_ips (ip, first_seen, last_checked, check_count, is_threat) VALUES (?, ?, ?, ?, ?)',
                        (ip, check_date, check_date, 1, 1 if is_threat else 0)
                    )
                
                # If it's a threat, update or insert into threats table
                if is_threat:
                    categories = ','.join(str(cat) for cat in report.get('reports', [{'categories': []}])[0].get('categories', []))
                    
                    c.execute('SELECT * FROM threats WHERE ip = ?', (ip,))
                    if c.fetchone():
                        c.execute(
                            'UPDATE threats SET abuse_score = ?, reports = ?, last_seen = ?, categories = ?, country = ? WHERE ip = ?',
                            (abuse_score, report.get('totalReports', 0), report.get('lastReportedAt', ''), categories, report.get('countryCode', ''), ip)
                        )
                    else:
                        c.execute(
                            'INSERT INTO threats (ip, abuse_score, reports, last_seen, categories, country) VALUES (?, ?, ?, ?, ?, ?)',
                            (ip, abuse_score, report.get('totalReports', 0), report.get('lastReportedAt', ''), categories, report.get('countryCode', ''))
                        )
                    
                    # Send email notification
                    send_email_notification(ip, report, config)
                    threats_detected += 1
                
                ips_checked += 1
                daily_checks += 1
            
            # Sleep briefly to avoid rate limiting
            time.sleep(0.5)
        
        # Update stats
        update_db_stats(conn, 'last_check', check_date)
        update_db_stats(conn, 'daily_checks', str(daily_checks))
        total_checks = int(get_db_stats(conn, 'total_checks') or '0') + ips_checked
        update_db_stats(conn, 'total_checks', str(total_checks))
        
        conn.commit()
        
        return {
            'status': 'ok',
            'message': f'Check completed. Checked {ips_checked} IPs, detected {threats_detected} threats.',
            'ips_checked': ips_checked,
            'threats_detected': threats_detected
        }
        
    except Exception as e:
        return {'status': 'error', 'message': f'Error during check: {str(e)}'}
    
    finally:
        conn.close()

def get_statistics():
    """Get statistics from the database"""
    if not os.path.exists(DB_FILE):
        return {'status': 'error', 'message': 'Database not initialized'}
    
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get total IPs checked
        c.execute('SELECT COUNT(*) as count FROM checked_ips')
        total_ips = c.fetchone()['count']
        
        # Get total threats
        c.execute('SELECT COUNT(*) as count FROM threats')
        total_threats = c.fetchone()['count']
        
        # Get last check time
        c.execute('SELECT value FROM stats WHERE key = ?', ('last_check',))
        last_check = c.fetchone()['value']
        
        # Get daily checks and limit
        c.execute('SELECT value FROM stats WHERE key = ?', ('daily_checks',))
        daily_checks = c.fetchone()['value']
        
        config = read_config()
        daily_limit = config['daily_check_limit']
        
        conn.close()
        
        return {
            'status': 'ok',
            'total_ips': total_ips,
            'total_threats': total_threats,
            'last_check': last_check,
            'daily_checks': daily_checks,
            'daily_limit': daily_limit
        }
    
    except Exception as e:
        return {'status': 'error', 'message': f'Error retrieving statistics: {str(e)}'}

def get_recent_threats():
    """Get the most recent threats from the database"""
    if not os.path.exists(DB_FILE):
        return {'status': 'error', 'message': 'Database not initialized'}
    
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get the 20 most recent threats
        c.execute('''
        SELECT t.ip, t.abuse_score, t.reports, t.last_seen, t.country, t.categories
        FROM threats t
        JOIN checked_ips c ON t.ip = c.ip
        ORDER BY c.last_checked DESC
        LIMIT 20
        ''')
        
        threats = []
        for row in c.fetchall():
            threats.append({
                'ip': row['ip'],
                'score': row['abuse_score'],
                'reports': row['reports'],
                'last_seen': row['last_seen'],
                'country': row['country'],
                'categories': row['categories']
            })
        
        conn.close()
        
        return {
            'status': 'ok',
            'threats': threats
        }
    
    except Exception as e:
        return {'status': 'error', 'message': f'Error retrieving threats: {str(e)}'}

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AbuseIPDB Checker')
    parser.add_argument('mode', choices=[MODE_CHECK, MODE_STATS, MODE_THREATS], help='Operation mode')
    args = parser.parse_args()
    
    if args.mode == MODE_CHECK:
        config = read_config()
        result = run_checker(config)
    elif args.mode == MODE_STATS:
        result = get_statistics()
    elif args.mode == MODE_THREATS:
        result = get_recent_threats()
    
    print(json.dumps(result))

if __name__ == '__main__':
    main()