#!/usr/bin/env python3
"""
OPNsense AbuseIPDB Integration Plugin
-------------------------------------
This plugin monitors firewall logs for incoming connections to LAN subnets,
checks source IPs against AbuseIPDB, and sends email notifications for threats.
Features:
- Focuses on external IPs attempting to connect to LAN subnets
- Reports destination ports in notifications
- Configurable protocol filtering
- Option to ignore blocked connections
- Daily API check limits
- Full WebGUI integration
"""

import os
import sys
import json
import time
import sqlite3
import smtplib
import requests
import argparse
import ipaddress
import subprocess
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from configparser import ConfigParser

# Default configuration file path
CONFIG_FILE = '/usr/local/etc/abuseipdb_checker.conf'
DB_FILE = '/var/db/abuseipdb_checker.db'

# Configure logging
log_file = '/var/log/abuseipdb_checker.log'
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Add a console handler as well for direct output
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# Create logger
logger = logging.getLogger('abuseipdb_checker')

class AbuseIPDBChecker:
    def __init__(self, config_path=CONFIG_FILE):
        # Load configuration
        self.config = ConfigParser()
        
        # Check if config file exists
        if not os.path.exists(config_path):
            logger.warning(f"Configuration file not found at {config_path}, creating default")
            self.create_default_config(config_path)
        self.config.read(config_path)
        
        # Check if API key is set to default
        if self.config.get('AbuseIPDB', 'APIKey') == 'YOUR_API_KEY_HERE':
            logger.error("API key not configured. Please update the configuration file.")
            sys.exit(1)
            
        # Initialize database
        self.init_database()
        
    def create_default_config(self, config_path):
        """Create a default configuration file if none exists"""
        self.config['General'] = {
            'LogFile': '/var/log/filter.log',
            'CheckFrequency': '7',  # days
            'AbuseScoreThreshold': '80',
            'DailyCheckLimit': '100',  # Max IPs to check per day
            'IgnoreBlockedConnections': 'true'  # Only examine allowed traffic
        }
        
        self.config['NetworkSettings'] = {
            'LANSubnets': '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12',  # LAN subnets to monitor
            'IgnoreProtocols': 'icmp,igmp'  # Protocols to ignore
        }
        
        self.config['AbuseIPDB'] = {
            'APIKey': 'YOUR_API_KEY_HERE',
            'APIEndpoint': 'https://www.abuseipdb.com/check',
            'MaxAge': '90'  # days to look back in AbuseIPDB reports
        }
        
        self.config['Email'] = {
            'Enabled': 'true',
            'SMTPServer': 'smtp.example.com',
            'SMTPPort': '587',
            'SMTPUsername': 'your_username',
            'SMTPPassword': 'your_password',
            'FromAddress': 'firewall@yourdomain.com',
            'ToAddress': 'admin@yourdomain.com',
            'UseTLS': 'true'
        }
        
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as configfile:
            self.config.write(configfile)
        
        logger.info(f"Created default configuration file at {config_path}")
        logger.info("Please edit this file to set your API key and other settings")

    def init_database(self):
        """Initialize the SQLite database to store checked IPs and daily stats"""
        # Ensure the directory exists
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Create IPs table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS checked_ips (
                ip TEXT PRIMARY KEY,
                last_checked TIMESTAMP,
                score INTEGER,
                is_threat BOOLEAN
            )
        ''')
        
        # Create table to track daily API usage
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS daily_stats (
                date TEXT PRIMARY KEY,
                checks_performed INTEGER
            )
        ''')
        
        # Create table to store connection details for reporting
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connection_details (
                ip TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                protocol TEXT,
                timestamp TIMESTAMP,
                PRIMARY KEY (ip, dest_ip, dest_port, protocol)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def validate_config(self):
        """Ensure all required configuration elements are present and valid"""
        required_sections = ['General', 'NetworkSettings', 'AbuseIPDB', 'Email']
        for section in required_sections:
            if not self.config.has_section(section):
                logger.error(f"Missing required configuration section: {section}")
                return False
                
        # Check key settings
        if not self.config.get('AbuseIPDB', 'APIKey') or self.config.get('AbuseIPDB', 'APIKey') == 'YOUR_API_KEY_HERE':
            logger.error("AbuseIPDB API key is not configured")
            return False
            
        return True

    def parse_firewall_logs(self):
        """
        Parse OPNsense firewall logs to extract source IPs targeting LAN subnets
        Returns a dictionary mapping IPs to details about their connections
        """
        log_file = self.config.get('General', 'LogFile')
        connection_data = {}
        
        # Get configuration settings
        lan_subnets_str = self.config.get('NetworkSettings', 'LANSubnets')
        lan_subnets = [ipaddress.ip_network(subnet.strip()) for subnet in lan_subnets_str.split(',')]
        
        ignore_protocols = [p.strip().lower() for p in 
                           self.config.get('NetworkSettings', 'IgnoreProtocols').split(',')]
        
        ignore_blocked = self.config.getboolean('General', 'IgnoreBlockedConnections')
        
        try:
            # Use tail to get the most recent log entries
            log_output = subprocess.check_output(['tail', '-n', '5000', log_file]).decode('utf-8')
            
            for line in log_output.splitlines():
                # Skip lines that don't match our criteria
                if ignore_blocked and 'block' in line:
                    continue
                    
                # Extract connection details
                try:
                    parts = line.split()
                    
                    # Find the protocol
                    protocol_idx = None
                    for idx, part in enumerate(parts):
                        if part.lower() in ('tcp', 'udp', 'icmp', 'igmp'):
                            protocol_idx = idx
                            break
                            
                    if protocol_idx is None:
                        continue
                        
                    protocol = parts[protocol_idx].lower()
                    
                    # Skip ignored protocols
                    if protocol in ignore_protocols:
                        continue
                    
                    # Look for source and destination IP and port
                    if len(parts) >= protocol_idx + 6:  # Ensure enough parts exist
                        src_ip = parts[protocol_idx + 2]
                        dst_ip = parts[protocol_idx + 3]
                        
                        dst_port = "n/a"
                        if protocol in ('tcp', 'udp') and len(parts) >= protocol_idx + 5:
                            dst_port = parts[protocol_idx + 4]
                        
                        # Validate IPs
                        src_ip_obj = ipaddress.ip_address(src_ip)
                        dst_ip_obj = ipaddress.ip_address(dst_ip)
                        
                        # Check if destination is in our LAN subnets
                        is_dest_in_lan = any(dst_ip_obj in subnet for subnet in lan_subnets)
                        
                        # Only include external IPs targeting our LAN
                        if not src_ip_obj.is_private and is_dest_in_lan:
                            if src_ip not in connection_data:
                                connection_data[src_ip] = []
                                
                            connection_data[src_ip].append({
                                'dest_ip': dst_ip,
                                'dest_port': dst_port,
                                'protocol': protocol,
                                'timestamp': datetime.now().isoformat()
                            })
                            
                            # Store connection details in database for reporting
                            conn = sqlite3.connect(DB_FILE)
                            cursor = conn.cursor()
                            cursor.execute('''
                                INSERT OR REPLACE INTO connection_details
                                (ip, dest_ip, dest_port, protocol, timestamp)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (src_ip, dst_ip, dst_port, protocol, datetime.now().isoformat()))
                            conn.commit()
                            conn.close()
                            
                except (ValueError, IndexError):
                    # Skip malformed log lines
                    continue
                                
        except Exception as e:
            logger.error(f"Error parsing firewall logs: {e}")
            
        return connection_data
        
    def should_check_ip(self, ip):
        """
        Determine if an IP should be checked based on:
        1. Last check time (to respect weekly check interval)
        2. Daily API check limit (to respect API usage constraints)
        """
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if IP was recently checked
        cursor.execute('''
            SELECT last_checked FROM checked_ips
            WHERE ip = ?
        ''', (ip,))
        
        result = cursor.fetchone()
        
        # If we've checked this IP before, verify it's been long enough since last check
        if result:
            last_checked = datetime.fromisoformat(result[0])
            check_frequency = int(self.config.get('General', 'CheckFrequency'))
            
            if datetime.now() - last_checked <= timedelta(days=check_frequency):
                conn.close()
                return False
        
        # Check against daily API limit
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute('''
            SELECT checks_performed FROM daily_stats
            WHERE date = ?
        ''', (today,))
        
        result = cursor.fetchone()
        daily_limit = int(self.config.get('General', 'DailyCheckLimit'))
        
        if result:
            checks_today = result[0]
            if checks_today >= daily_limit:
                logger.warning(f"Daily API check limit of {daily_limit} reached. Skipping remaining IPs.")
                conn.close()
                return False
        
        conn.close()
        return True
        
    def update_daily_check_count(self):
        """Updates the daily check count in the database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        today = datetime.now().strftime('%Y-%m-%d')
        
        cursor.execute('''
            INSERT INTO daily_stats (date, checks_performed)
            VALUES (?, 1)
            ON CONFLICT(date) DO UPDATE SET
            checks_performed = checks_performed + 1
        ''', (today,))
        
        conn.commit()
        conn.close()
    
    def get_connection_details_for_ip(self, ip):
        """Retrieves all connection details for a given IP from the database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT dest_ip, dest_port, protocol, timestamp
            FROM connection_details
            WHERE ip = ?
            ORDER BY timestamp DESC
        ''', (ip,))
        
        details = cursor.fetchall()
        conn.close()
        
        return details
    
    def check_ip_against_abuseipdb(self, ip):
        """Check an IP against the AbuseIPDB API"""
        api_key = self.config.get('AbuseIPDB', 'APIKey')
        max_age = self.config.get('AbuseIPDB', 'MaxAge')
        
        # Use the proper API endpoint format
        api_endpoint = f"https://www.abuseipdb.com/check/{ip}/json"
        
        params = {
            'key': api_key,
            'days': max_age
        }
        
        try:
            response = requests.get(api_endpoint, params=params)
            response.raise_for_status()
            
            # Update daily API check count
            self.update_daily_check_count()
            
            data = response.json()
            
            # Handle the response based on the API structure
            if 'data' in data:
                score = data['data'].get('abuseConfidenceScore', 0)
                threshold = int(self.config.get('General', 'AbuseScoreThreshold'))
                is_threat = score >= threshold
                
                # Update database
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO checked_ips
                    (ip, last_checked, score, is_threat)
                    VALUES (?, ?, ?, ?)
                ''', (ip, datetime.now().isoformat(), score, is_threat))
                
                conn.commit()
                conn.close()
                
                if is_threat:
                    self.send_threat_notification(ip, score, data['data'])
                    
                return is_threat
                
        except Exception as e:
            logger.error(f"Error checking IP {ip} against AbuseIPDB: {e}")
            
        return False
        
    def send_threat_notification(self, ip, score, details):
        """Send an email notification about a potential threat with connection details"""
        if not self.config.getboolean('Email', 'Enabled'):
            return
            
        smtp_server = self.config.get('Email', 'SMTPServer')
        smtp_port = self.config.getint('Email', 'SMTPPort')
        smtp_user = self.config.get('Email', 'SMTPUsername')
        smtp_pass = self.config.get('Email', 'SMTPPassword')
        from_addr = self.config.get('Email', 'FromAddress')
        to_addr = self.config.get('Email', 'ToAddress')
        use_tls = self.config.getboolean('Email', 'UseTLS')
        
        # Create email content
        msg = MIMEMultipart()
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Subject'] = f"Firewall Alert: Potential Threat from {ip}"
        
        # Get connection details for this IP
        connection_details = self.get_connection_details_for_ip(ip)
        
        # Prepare connection details HTML
        connection_html = ""
        if connection_details:
            connection_html = """
            <h3>Connection Attempts</h3>
            <table border="1" cellpadding="5">
                <tr>
                    <th>Destination IP</th>
                    <th>Destination Port</th>
                    <th>Protocol</th>
                    <th>Timestamp</th>
                </tr>
            """
            
            # Limit to 10 most recent connections to keep email reasonable
            for dest_ip, dest_port, protocol, timestamp in connection_details[:10]:
                connection_html += f"""
                <tr>
                    <td>{dest_ip}</td>
                    <td>{dest_port}</td>
                    <td>{protocol.upper()}</td>
                    <td>{timestamp}</td>
                </tr>
                """
                
            if len(connection_details) > 10:
                connection_html += f"""
                <tr>
                    <td colspan="4"><em>And {len(connection_details) - 10} more connection attempts...</em></td>
                </tr>
                """
                
            connection_html += "</table>"
        
        # Prepare email body
        body = f"""
        <html>
        <body>
            <h2>Firewall Alert: Potential Threat Detected</h2>
            <p>The OPNsense AbuseIPDB Checker has identified a potential threat:</p>
            
            <table border="1" cellpadding="5">
                <tr>
                    <th>IP Address</th>
                    <td>{ip}</td>
                </tr>
                <tr>
                    <th>Abuse Confidence Score</th>
                    <td>{score}%</td>
                </tr>
                <tr>
                    <th>Country</th>
                    <td>{details.get('countryName', 'Unknown')}</td>
                </tr>
                <tr>
                    <th>ISP</th>
                    <td>{details.get('isp', 'Unknown')}</td>
                </tr>
                <tr>
                    <th>Domain</th>
                    <td>{details.get('domain', 'Unknown')}</td>
                </tr>
                <tr>
                    <th>Total Reports</th>
                    <td>{details.get('totalReports', 'Unknown')}</td>
                </tr>
                <tr>
                    <th>Last Reported</th>
                    <td>{details.get('lastReportedAt', 'Unknown')}</td>
                </tr>
            </table>
            
            {connection_html}
            
            <p>For more information, visit:</p>
            <p><a href="https://www.abuseipdb.com/check/{ip}">https://www.abuseipdb.com/check/{ip}</a></p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            if use_tls:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
            server.quit()
            logger.warning(f"Potential threat: Sent notification email for IP {ip} with score {score}")
        except Exception as e:
            logger.error(f"Error sending email: {e}")
    
    def run(self):
        """Main execution method"""
        logger.info("Starting OPNsense AbuseIPDB Checker...")
        
        # Get connection data from firewall logs
        connection_data = self.parse_firewall_logs()
        source_ips = list(connection_data.keys())
        logger.info(f"Found {len(source_ips)} unique external IPs targeting LAN subnets")
        
        # Check each IP against AbuseIPDB if needed
        checked = 0
        threats = 0
        daily_limit = int(self.config.get('General', 'DailyCheckLimit'))
        
        for ip in source_ips:
            # Stop if we've reached the daily limit
            if checked >= daily_limit:
                logger.warning(f"Daily check limit of {daily_limit} reached. Stopping.")
                break
                
            if self.should_check_ip(ip):
                logger.info(f"Checking IP: {ip}")
                is_threat = self.check_ip_against_abuseipdb(ip)
                checked += 1
                if is_threat:
                    threats += 1
                    
                # Be nice to the API and avoid rate limiting
                time.sleep(1)
            else:
                logger.info(f"Skipping IP {ip} (recently checked or limit reached)")
                
        logger.info(f"Checked {checked} IPs, found {threats} potential threats")

def main():
    parser = argparse.ArgumentParser(description='OPNsense AbuseIPDB Integration')
    parser.add_argument('--config', help='Path to configuration file', default=CONFIG_FILE)
    parser.add_argument('--create-config', action='store_true', help='Create default configuration file only')
    args = parser.parse_args()
    
    checker = AbuseIPDBChecker(args.config)
    
    if args.create_config:
        # Just create the config file and exit successfully
        return
        
    checker.run()

if __name__ == "__main__":
    main()
