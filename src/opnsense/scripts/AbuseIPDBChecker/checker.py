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
# Make sure all imports are at the top, with error handling
try:
    import os
    import sys
    import time
    import json
    import sqlite3
    import ipaddress
    import re
    import smtplib
    import argparse
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from datetime import datetime, timedelta
    from configparser import ConfigParser
    
    # Check for requests package
    try:
        import requests
    except ImportError:
        print("Error: Python requests package not installed", file=sys.stderr)
        print('{"status": "error", "message": "Python requests package not installed. Run: pkg install py39-requests"}')
        sys.exit(1)
        
except ImportError as e:
    # Handle import errors gracefully
    print(f"Error importing required modules: {str(e)}", file=sys.stderr)
    print(f'{{"status": "error", "message": "Missing required Python module: {str(e)}"}}')
    sys.exit(1)

# Constants
DB_DIR = '/var/db/abuseipdbchecker'
DB_FILE = os.path.join(DB_DIR, 'abuseipdb.db')
CONFIG_FILE = '/usr/local/etc/abuseipdbchecker/abuseipdbchecker.conf'
LOG_DIR = '/var/log/abuseipdbchecker'
LOG_FILE = os.path.join(LOG_DIR, 'abuseipdb.log')

# Command modes
MODE_CHECK = 'check'
MODE_STATS = 'stats'
MODE_THREATS = 'threats'

def ensure_directories():
    """Ensure all required directories exist with correct permissions"""
    dirs = [
        (DB_DIR, 0o755),
        (LOG_DIR, 0o755),
        (os.path.dirname(CONFIG_FILE), 0o755)
    ]
    
    for directory, mode in dirs:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory, mode=mode)
                print(f"Created directory: {directory}", file=sys.stderr)
                
                # Try to set ownership to www user (for web server access)
                try:
                    import subprocess
                    subprocess.run(['chown', '-R', 'www:www', directory], check=False)
                except Exception as e:
                    print(f"Note: Could not set ownership for {directory}: {str(e)}", file=sys.stderr)
            except Exception as e:
                print(f"Error creating directory {directory}: {str(e)}", file=sys.stderr)
                # Continue anyway - we'll handle errors at the point of file access

def system_log(message, priority=5):
    """Log to system log as fallback"""
    try:
        import syslog
        syslog.openlog("abuseipdbchecker")
        syslog.syslog(priority, message)
        syslog.closelog()
    except Exception as e:
        print(f"Error writing to syslog: {str(e)}", file=sys.stderr)

def log_message(message):
    """Log a message to the log file"""
    log_dir = '/var/log/abuseipdbchecker'
    log_file = os.path.join(log_dir, 'abuseipdb.log')
    
    try:
        # Create log directory if it doesn't exist
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, mode=0o755)
                # Try to set ownership to www user (web server)
                try:
                    import subprocess
                    subprocess.run(['chown', '-R', 'www:www', log_dir], check=False)
                except Exception as e:
                    print(f"Error setting log directory ownership: {str(e)}", file=sys.stderr)
            except Exception as e:
                print(f"Error creating log directory: {str(e)}", file=sys.stderr)
                return
        
        # Check if this is a startup message that should be suppressed
        if "Script started successfully" in message and os.path.exists(log_file):
            # Skip logging repetitive startup messages
            return
            
        # Append message to log file
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
        
        # Make sure log file has permissive permissions
        try:
            os.chmod(log_file, 0o666)  # Make world-readable and writable
            try:
                import subprocess
                subprocess.run(['chown', 'www:www', log_file], check=False)
            except Exception as e:
                print(f"Error setting log file ownership: {str(e)}", file=sys.stderr)
        except Exception as e:
            print(f"Error setting log file permissions: {str(e)}", file=sys.stderr)
    
    except Exception as e:
        print(f"Error writing to log: {str(e)}", file=sys.stderr)
        # Try to write to system log as fallback
        try:
            import syslog
            syslog.openlog("abuseipdbchecker")
            syslog.syslog(syslog.LOG_ERR, f"Error writing to log file: {str(e)}")
            syslog.syslog(syslog.LOG_NOTICE, f"Original message: {message}")
            syslog.closelog()
        except Exception:
            pass  # Last resort, if even syslog fails, just silently continue

def read_config():
    """Read configuration from OPNsense config file"""
    config = {
        'enabled': False,
        'log_file': '/var/log/filter/latest.log',
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
    """Parse OPNsense firewall log for external IPs"""
    external_ips = set()
    
    if not os.path.exists(config['log_file']):
        log_message(f"Log file not found: {config['log_file']}")
        return external_ips
    
    # Convert LAN subnets to proper network objects
    lan_networks = []
    for subnet in config['lan_subnets']:
        try:
            lan_networks.append(ipaddress.ip_network(subnet.strip()))
        except ValueError as e:
            log_message(f"Invalid LAN subnet: {subnet} - {str(e)}")
            continue
    
    log_message(f"Parsing OPNsense log file: {config['log_file']}")
    
    try:
        line_count = 0
        parsed_entries = 0
        
        with open(config['log_file'], 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_count += 1
                line = line.strip()
                
                if not line or 'filterlog' not in line:
                    continue
                
                try:
                    # Extract the structured log data after the syslog header
                    if '] ' in line:
                        csv_part = line.split('] ', 1)[1]
                    else:
                        continue
                    
                    # Split CSV data
                    fields = csv_part.split(',')
                    
                    # Ensure we have enough fields
                    if len(fields) < 20:
                        continue
                    
                    # Correct field positions for OPNsense/pfSense format
                    action = fields[6].strip() if len(fields) > 6 else ''
                    direction = fields[7].strip() if len(fields) > 7 else ''
                    ip_version = fields[8].strip() if len(fields) > 8 else ''
                    
                    # Only process IPv4 for now
                    if ip_version != '4':
                        continue
                    
                    # Skip blocked connections if configured
                    if config['ignore_blocked_connections'] and action.lower() == 'block':
                        continue
                    
                    # For IPv4, protocol is at position 15, src_ip varies by protocol
                    if len(fields) > 15:
                        try:
                            proto_num = int(fields[15].strip())
                            
                            # Skip ignored protocols by number
                            proto_name = ''
                            if proto_num == 1:
                                proto_name = 'icmp'
                            elif proto_num == 2:
                                proto_name = 'igmp'
                            elif proto_num == 6:
                                proto_name = 'tcp'
                            elif proto_num == 17:
                                proto_name = 'udp'
                            else:
                                proto_name = str(proto_num)
                            
                            if proto_name.lower() in [p.lower() for p in config['ignore_protocols']]:
                                continue
                            
                            # For IPv4 TCP/UDP, source IP is typically at position 17, destination at 18
                            if proto_num in [6, 17] and len(fields) > 18:  # TCP or UDP
                                src_ip = fields[17].strip() if len(fields) > 17 else ''
                                dst_ip = fields[18].strip() if len(fields) > 18 else ''
                            elif len(fields) > 16:  # Other protocols  
                                src_ip = fields[16].strip() if len(fields) > 16 else ''
                                dst_ip = fields[17].strip() if len(fields) > 17 else ''
                            else:
                                continue
                                
                        except (ValueError, IndexError):
                            continue
                    else:
                        continue
                    
                    # Process based on direction
                    if direction.lower() == 'in' and src_ip:
                        # Incoming traffic - external source
                        ip = src_ip
                    elif direction.lower() == 'out' and dst_ip:
                        # Outgoing traffic - external destination  
                        ip = dst_ip
                    else:
                        continue
                            
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        
                        # Skip localhost, multicast, reserved ranges
                        if (ip_obj.is_loopback or 
                            ip_obj.is_multicast or 
                            ip_obj.is_reserved or
                            ip_obj.is_link_local):
                            continue
                        
                        # Skip RFC 1918 private addresses
                        if ip_obj.is_private:
                            continue
                        
                        # Skip if IP is in any configured LAN subnet
                        is_lan_ip = False
                        for network in lan_networks:
                            try:
                                if ip_obj in network:
                                    is_lan_ip = True
                                    break
                            except ValueError:
                                continue
                        
                        if not is_lan_ip:
                            external_ips.add(ip)
                            parsed_entries += 1
                            
                    except ValueError:
                        # Invalid IP address
                        continue
                        
                except Exception as e:
                    # Skip malformed lines
                    continue
        
        log_message(f"Processed {line_count} lines, parsed {parsed_entries} entries, found {len(external_ips)} unique external IPs")
        
        # Log sample of found IPs for debugging
        if external_ips:
            sample_ips = sorted(list(external_ips))[:10]
            log_message(f"Sample external IPs found: {', '.join(sample_ips)}")
        else:
            log_message("No external IPs found - check log file and field positions")
        
    except Exception as e:
        log_message(f"Error reading log file: {str(e)}")
    
    return external_ips

def debug_real_parsing():
    """Debug current log parsing in real-time with detailed filtering steps"""
    config = read_config()
    
    if not os.path.exists(config['log_file']):
        return {'status': 'error', 'message': f"Log file not found: {config['log_file']}"}
    
    stat = os.stat(config['log_file'])
    file_size = stat.st_size
    file_modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
    
    # Parse last 50 lines for debugging
    debug_results = {
        'file_info': {
            'path': config['log_file'],
            'size_mb': round(file_size / 1024 / 1024, 2),
            'last_modified': file_modified
        },
        'config': {
            'ignore_blocked': config['ignore_blocked_connections'],
            'ignore_protocols': config['ignore_protocols'],
            'lan_subnets': config['lan_subnets']
        },
        'processing_steps': [],
        'filtered_out': {'blocked': [], 'protocols': [], 'private_ips': [], 'lan_ips': []},
        'accepted_ips': []
    }
    
    # Convert LAN subnets to network objects
    lan_networks = []
    for subnet in config['lan_subnets']:
        try:
            lan_networks.append(ipaddress.ip_network(subnet.strip()))
        except ValueError:
            continue
    
    # Read last 100 lines
    with open(config['log_file'], 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
        recent_lines = lines[-100:] if len(lines) > 100 else lines
    
    processed_count = 0
    for line in recent_lines:
        line = line.strip()
        if not line or 'filterlog' not in line:
            continue
            
        try:
            # Parse line
            if '] ' in line:
                csv_part = line.split('] ', 1)[1]
                fields = csv_part.split(',')
                
                if len(fields) < 20:
                    continue
                
                action = fields[6].strip()
                direction = fields[7].strip()
                proto = fields[16].strip()
                src_ip = fields[18].strip()
                dst_ip = fields[19].strip()
                
                step = {
                    'line_num': processed_count + 1,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'direction': direction,
                    'action': action,
                    'protocol': proto,
                    'result': 'unknown'
                }
                
                # Apply filters step by step
                if direction.lower() != 'in':
                    step['result'] = 'skipped_not_incoming'
                elif not src_ip:
                    step['result'] = 'skipped_no_src_ip'
                elif config['ignore_blocked_connections'] and action.lower() == 'block':
                    step['result'] = 'filtered_blocked'
                    debug_results['filtered_out']['blocked'].append(src_ip)
                elif proto.lower() in [p.lower() for p in config['ignore_protocols']]:
                    step['result'] = 'filtered_protocol'
                    debug_results['filtered_out']['protocols'].append(src_ip)
                else:
                    # Check IP validity and networks
                    try:
                        ip_obj = ipaddress.ip_address(src_ip)
                        
                        if ip_obj.is_private:
                            step['result'] = 'filtered_private'
                            debug_results['filtered_out']['private_ips'].append(src_ip)
                        elif any(ip_obj in network for network in lan_networks):
                            step['result'] = 'filtered_lan'
                            debug_results['filtered_out']['lan_ips'].append(src_ip)
                        else:
                            step['result'] = 'ACCEPTED'
                            debug_results['accepted_ips'].append(src_ip)
                            
                    except ValueError:
                        step['result'] = 'filtered_invalid_ip'
                
                debug_results['processing_steps'].append(step)
                processed_count += 1
                
                if processed_count >= 20:  # Limit output
                    break
                    
        except Exception as e:
            continue
    
    # Get unique accepted IPs
    debug_results['unique_accepted'] = list(set(debug_results['accepted_ips']))
    debug_results['summary'] = {
        'total_processed': processed_count,
        'unique_external_ips': len(debug_results['unique_accepted']),
        'blocked_filtered': len(set(debug_results['filtered_out']['blocked'])),
        'protocol_filtered': len(set(debug_results['filtered_out']['protocols'])),
        'private_filtered': len(set(debug_results['filtered_out']['private_ips'])),
        'lan_filtered': len(set(debug_results['filtered_out']['lan_ips']))
    }
    
    return {'status': 'ok', 'debug': debug_results}

def debug_log_parsing():
    """Debug function to test OPNsense log parsing with detailed output"""
    config = read_config()
    
    if not os.path.exists(config['log_file']):
        return {'status': 'error', 'message': f"Log file not found: {config['log_file']}"}
    
    sample_lines = []
    parsed_entries = []
    all_ips_found = []
    
    with open(config['log_file'], 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= 10:  # First 10 filterlog lines
                break
                
            if 'filterlog' not in line:
                continue
                
            sample_lines.append(line.strip())
            
            try:
                # Parse the line
                if '] ' in line:
                    csv_part = line.split('] ', 1)[1]
                    fields = csv_part.split(',')
                    
                    if len(fields) >= 20:
                        entry = {
                            'action': fields[6].strip(),
                            'direction': fields[7].strip(),
                            'protocol': fields[16].strip(),
                            'src_ip': fields[18].strip(),
                            'dst_ip': fields[19].strip(),
                            'src_port': fields[20].strip() if len(fields) > 20 else '',
                            'dst_port': fields[21].strip() if len(fields) > 21 else ''
                        }
                        parsed_entries.append(entry)
                        
                        # Collect all IPs
                        for ip in [entry['src_ip'], entry['dst_ip']]:
                            if ip:
                                all_ips_found.append(ip)
                                
            except Exception as e:
                parsed_entries.append({'error': str(e), 'line': line[:100]})
    
    # Run actual parsing
    external_ips = parse_log_for_ips(config)
    
    return {
        'status': 'ok',
        'log_file': config['log_file'],
        'sample_lines_count': len(sample_lines),
        'parsed_entries': parsed_entries,
        'all_ips_found': list(set(all_ips_found)),
        'external_ips_detected': sorted(list(external_ips)),
        'config_settings': {
            'lan_subnets': config['lan_subnets'],
            'ignore_protocols': config['ignore_protocols'],
            'ignore_blocked': config['ignore_blocked_connections']
        }
    }

def check_ip_abuseipdb(ip, config):
    """Check an IP against AbuseIPDB API"""
    if not config['api_key']:
        log_message("API key not configured")
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
        # Log API request for debugging
        log_message(f"Sending API request to {config['api_endpoint']} for IP {ip}")
        
        response = requests.get(
            config['api_endpoint'], 
            headers=headers, 
            params=params,
            timeout=10  # Add timeout to prevent hanging
        )
        
        # Log API response status code
        log_message(f"API response status code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            log_message(f"API response received: {data.get('data', {}).get('abuseConfidenceScore')}% confidence score")
            return data.get('data', {})
        elif response.status_code == 401:
            log_message(f"API error: Authentication failed - invalid API key")
            raise Exception("Authentication failed - invalid API key")
        elif response.status_code == 429:
            log_message(f"API error: Rate limit exceeded")
            raise Exception("Rate limit exceeded - please try again later")
        else:
            log_message(f"API error: {response.status_code} - {response.text}")
            raise Exception(f"API error: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        log_message(f"Connection error: {str(e)}")
        raise Exception(f"Connection error: {str(e)}")
    except Exception as e:
        log_message(f"Error checking IP {ip}: {str(e)}")
        raise Exception(f"Error checking IP: {str(e)}")

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
    
    conn = None
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
        
        # Get last check time with fallback
        c.execute('SELECT value FROM stats WHERE key = ?', ('last_check',))
        row = c.fetchone()
        last_check = row['value'] if row else 'Never'
        
        # Get daily checks with fallback
        c.execute('SELECT value FROM stats WHERE key = ?', ('daily_checks',))
        row = c.fetchone()
        daily_checks = row['value'] if row else '0'
        
        config = read_config()
        daily_limit = config['daily_check_limit']
        
        return {
            'status': 'ok',
            'total_ips': total_ips,
            'total_threats': total_threats,
            'last_check': last_check,
            'daily_checks': daily_checks,
            'daily_limit': daily_limit
        }
    
    except Exception as e:
        log_message(f"Error retrieving statistics: {str(e)}")
        return {'status': 'error', 'message': f'Error retrieving statistics: {str(e)}'}
    finally:
        if conn:
            conn.close()

def get_recent_threats():
    """Get the most recent threats from the database"""
    if not os.path.exists(DB_FILE):
        return {'status': 'error', 'message': 'Database not initialized'}
    
    conn = None
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
        
        return {
            'status': 'ok',
            'threats': threats
        }
    
    except Exception as e:
        log_message(f"Error retrieving threats: {str(e)}")
        return {'status': 'error', 'message': f'Error retrieving threats: {str(e)}'}
    finally:
        if conn:
            conn.close()

def get_logs():
    """Get the recent logs from the process"""
    log_dir = '/var/log/abuseipdbchecker'
    log_file = os.path.join(log_dir, 'abuseipdb.log')
    
    try:
        # Create log directory if it doesn't exist
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, mode=0o755)
                # Try to set ownership to www user
                try:
                    import subprocess
                    subprocess.run(['chown', '-R', 'www:www', log_dir], check=False)
                except Exception as e:
                    print(f"Error setting log directory ownership: {str(e)}", file=sys.stderr)
            except (OSError, PermissionError) as e:
                return {'status': 'error', 'message': f'Error creating log directory: {str(e)}. Check permissions.'}
            
        # If log file doesn't exist yet, create it with initial content
        if not os.path.exists(log_file):
            try:
                with open(log_file, 'w') as f:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"[{timestamp}] AbuseIPDB Checker logs initialized\n")
                # Make sure log file has permissive permissions
                os.chmod(log_file, 0o666)  # Make world-readable and writable
                try:
                    import subprocess
                    subprocess.run(['chown', 'www:www', log_file], check=False)
                except Exception as e:
                    print(f"Error setting log file ownership: {str(e)}", file=sys.stderr)
            except (IOError, PermissionError) as e:
                return {'status': 'error', 'message': f'Error creating log file: {str(e)}. Check permissions.'}
        
        # Read log file contents
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                if not content.strip():
                    return {'status': 'ok', 'logs': ['No important log entries found.']}
                    
                # Split by lines and filter out verbose debug messages
                lines = content.splitlines()
                
                # Filter out verbose debug lines
                filtered_lines = []
                verbose_patterns = [
                    'Running in',
                    'Retrieving',
                    'Operation completed with status: ok',
                    'Script started successfully',
                    'Configuration loaded',
                    'Poll completed successfully',
                    'sleeping for 5 seconds',
                    'Polling for external IPs',
                    'Would check these IPs',
                    'API calls disabled in daemon mode',
                    'continuing to poll',
                    'Database stats:',
                    'Found 0 external IPs',
                    'No external IPs found in current',
                ]
                
                for line in lines:
                    # Skip empty lines
                    if not line.strip():
                        continue
                        
                    # Check if line contains any verbose patterns
                    is_verbose = False
                    for pattern in verbose_patterns:
                        if pattern.lower() in line.lower():
                            is_verbose = True
                            break
                    
                    # Only include non-verbose lines
                    if not is_verbose:
                        filtered_lines.append(line)
                
                # Get last 50 important lines and reverse them (most recent first)
                important_lines = filtered_lines[-50:] if len(filtered_lines) > 50 else filtered_lines
                important_lines.reverse()  # Most recent at top
                
                if not important_lines:
                    return {'status': 'ok', 'logs': ['No important log entries found.']}
                    
                return {'status': 'ok', 'logs': important_lines}
                
        except (IOError, PermissionError) as e:
            return {'status': 'error', 'message': f'Error reading log file: {str(e)}. Check permissions.'}
        
    except Exception as e:
        print(f"Error retrieving logs: {str(e)}", file=sys.stderr)
        return {'status': 'error', 
                'message': f'Error retrieving logs: {str(e)}. Try: chmod -R 755 /var/log/abuseipdbchecker'}

def test_ip(ip_address):
    """Test a single IP against AbuseIPDB"""
    log_message(f"Starting test of IP: {ip_address}")
    
    # Validate IP address format
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        log_message(f"Invalid IP address: {ip_address}")
        return {'status': 'error', 'message': f'Invalid IP address format: {ip_address}'}
    
    config = read_config()
    log_message(f"Config loaded, enabled: {config['enabled']}, API key set: {'Yes' if config['api_key'] else 'No'}")
    
    if not config['enabled']:
        log_message("AbuseIPDBChecker is disabled in settings")
        return {'status': 'error', 'message': 'AbuseIPDBChecker is disabled in settings. Enable it in the General tab.'}
    
    if not config['api_key']:
        log_message("API key not configured")
        return {'status': 'error', 'message': 'API key not configured. Add your API key in the API tab.'}
    
    if config['api_key'] == 'YOUR_API_KEY':
        log_message("Default API key is being used")
        return {'status': 'error', 'message': 'Please configure a valid API key in the API tab. The default placeholder key cannot be used.'}
    
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        
        # Check IP against AbuseIPDB
        log_message(f"Checking IP {ip_address} with AbuseIPDB API")
        
        try:
            report = check_ip_abuseipdb(ip_address, config)
        except Exception as e:
            log_message(f"API request failed: {str(e)}")
            return {'status': 'error', 'message': f'API request failed: {str(e)}. Check your internet connection and API key.'}
        
        if report is None:
            log_message("API returned no data")
            return {'status': 'error', 'message': 'Error checking IP with AbuseIPDB API. The API returned no data.'}
        
        log_message(f"API response received for {ip_address}")
        
        c = conn.cursor()
        check_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        abuse_score = report.get('abuseConfidenceScore', 0)
        is_threat = abuse_score >= config['abuse_score_threshold']
        
        log_message(f"IP {ip_address}: Score={abuse_score}, Threshold={config['abuse_score_threshold']}, IsThreat={is_threat}")
        
        # Update daily checks count
        daily_checks = int(get_db_stats(conn, 'daily_checks') or '0')
        update_db_stats(conn, 'daily_checks', str(daily_checks + 1))
        
        # Update or insert into checked_ips (ALWAYS update last_checked)
        c.execute('SELECT * FROM checked_ips WHERE ip = ?', (ip_address,))
        existing = c.fetchone()
        
        if existing:
            c.execute(
                'UPDATE checked_ips SET last_checked = ?, check_count = check_count + 1, is_threat = ? WHERE ip = ?',
                (check_date, 1 if is_threat else 0, ip_address)
            )
            log_message(f"Updated checked_ips for {ip_address}: last_checked={check_date}")
        else:
            c.execute(
                'INSERT INTO checked_ips (ip, first_seen, last_checked, check_count, is_threat) VALUES (?, ?, ?, ?, ?)',
                (ip_address, check_date, check_date, 1, 1 if is_threat else 0)
            )
            log_message(f"Inserted into checked_ips for {ip_address}: last_checked={check_date}")
        
        # Handle threats table - ALWAYS update if IP is a threat
        if is_threat:
            log_message(f"Processing threat: {ip_address} (Score: {abuse_score})")
            
            # Get categories if available
            categories = ''
            if 'reports' in report and report['reports'] and len(report['reports']) > 0:
                if 'categories' in report['reports'][0]:
                    categories = ','.join(str(cat) for cat in report['reports'][0]['categories'])
            
            # Check if threat already exists
            c.execute('SELECT * FROM threats WHERE ip = ?', (ip_address,))
            existing_threat = c.fetchone()
            
            if existing_threat:
                c.execute(
                    'UPDATE threats SET abuse_score = ?, reports = ?, last_seen = ?, categories = ?, country = ? WHERE ip = ?',
                    (abuse_score, report.get('totalReports', 0), check_date, 
                     categories, report.get('countryCode', ''), ip_address)
                )
                log_message(f"Updated threats table for {ip_address}: last_seen={check_date}")
            else:
                c.execute(
                    'INSERT INTO threats (ip, abuse_score, reports, last_seen, categories, country) VALUES (?, ?, ?, ?, ?, ?)',
                    (ip_address, abuse_score, report.get('totalReports', 0), check_date, 
                     categories, report.get('countryCode', ''))
                )
                log_message(f"Inserted into threats table for {ip_address}: last_seen={check_date}")
            
            # Send email notification if enabled
            try:
                send_email_notification(ip_address, report, config)
            except Exception as e:
                log_message(f"Failed to send email notification: {str(e)}")
        else:
            log_message(f"Clean IP tested: {ip_address} (Score: {abuse_score})")
            # Remove from threats table if it exists but is no longer a threat
            c.execute('DELETE FROM threats WHERE ip = ?', (ip_address,))
            if c.rowcount > 0:
                log_message(f"Removed {ip_address} from threats table (no longer a threat)")
        
        conn.commit()
        
        # Update total checks
        total_checks = int(get_db_stats(conn, 'total_checks') or '0') + 1
        update_db_stats(conn, 'total_checks', str(total_checks))
        
        # Update last check time
        update_db_stats(conn, 'last_check', check_date)
        
        # Prepare result - ensure all values are strings to avoid JSON encoding issues
        result = {
            "status": "ok",
            "ip": ip_address,
            "is_threat": is_threat,
            "abuse_score": abuse_score,
            "country": str(report.get("countryCode", "Unknown")),
            "isp": str(report.get("isp", "Unknown")),
            "domain": str(report.get("domain", "Unknown")),
            "reports": report.get("totalReports", 0),
            "last_reported": str(report.get("lastReportedAt", "Never"))
        }
        
        # Convert any None values to empty strings
        for key, value in result.items():
            if value is None:
                result[key] = ""
                
        log_message(f"Test completed for {ip_address}: {'Threat' if is_threat else 'Clean'} (Score: {abuse_score})")
        return result
        
    except Exception as e:
        log_message(f"Error in test_ip function for {ip_address}: {str(e)}")
        return {"status": "error", "message": f"Error processing request: {str(e)}"}
    
    finally:
        if conn:
            conn.close()

def run_daemon():
    """Run the checker in daemon mode with 5-second polling"""
    log_message("AbuseIPDB Checker daemon starting up - PID: " + str(os.getpid()))
    
    # Set up signal handlers for graceful shutdown
    import signal
    
    def signal_handler(signum, frame):
        log_message(f"Received signal {signum}, stopping daemon gracefully")
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    poll_count = 0
    
    while True:
        try:
            poll_count += 1
            log_message(f"=== Daemon Poll #{poll_count} - PID {os.getpid()} ===")
            log_message("Polling for external IPs from firewall logs...")
            
            # Read configuration
            config = read_config()
            log_message(f"Configuration loaded - Enabled: {config['enabled']}")
            
            if not config['enabled']:
                log_message("Service is disabled in configuration, continuing to poll...")
                time.sleep(5)
                continue
            
            # Get external IPs from log (for debugging, we'll always show this)
            try:
                external_ips = parse_log_for_ips(config)
                
                if external_ips:
                    log_message(f"Found {len(external_ips)} external IPs from firewall logs")
                    # Show first few IPs for debugging
                    sample_ips = list(external_ips)[:3]
                    for ip in sample_ips:
                        log_message(f"  - External IP detected: {ip}")
                    if len(external_ips) > 3:
                        log_message(f"  - ... and {len(external_ips) - 3} more IPs")
                        
                    # For debugging, we'll show what we would do
                    log_message("Would check these IPs against AbuseIPDB (API calls disabled in daemon mode)")
                else:
                    log_message("No external IPs found in current firewall logs")
                    
            except Exception as e:
                log_message(f"Error parsing firewall logs: {str(e)}")
            
            # Check database stats
            try:
                if os.path.exists(DB_FILE):
                    conn = sqlite3.connect(DB_FILE)
                    c = conn.cursor()
                    c.execute('SELECT COUNT(*) FROM checked_ips')
                    total_ips = c.fetchone()[0]
                    c.execute('SELECT COUNT(*) FROM threats')
                    total_threats = c.fetchone()[0]
                    conn.close()
                    log_message(f"Database stats: {total_ips} IPs checked, {total_threats} threats detected")
                else:
                    log_message("Database not yet initialized")
            except Exception as e:
                log_message(f"Error reading database stats: {str(e)}")
            
            log_message("Poll completed successfully, sleeping for 5 seconds...")
            time.sleep(5)
            
        except KeyboardInterrupt:
            log_message("Received keyboard interrupt, stopping daemon")
            break
        except Exception as e:
            log_message(f"Error in daemon loop: {str(e)}")
            log_message("Continuing daemon operation...")
            time.sleep(5)
    
    log_message("AbuseIPDB Checker daemon shutting down")

def list_external_ips():
    """List external IPs from firewall logs without checking them"""
    try:
        config = read_config()
        
        if not config['enabled']:
            return {'status': 'disabled', 'message': 'AbuseIPDBChecker is disabled'}
            
        # Get external IPs from log
        external_ips = parse_log_for_ips(config)
        
        if not external_ips:
            return {'status': 'ok', 'message': 'No external IPs found', 'ips': []}
        
        # Convert set to sorted list for better display
        ip_list = sorted(list(external_ips))
        
        # Check database for any existing information about these IPs
        results = []
        
        if os.path.exists(DB_FILE):
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            for ip in ip_list:
                # Check if IP exists in database
                c.execute('SELECT last_checked, is_threat FROM checked_ips WHERE ip = ?', (ip,))
                db_row = c.fetchone()
                
                ip_info = {
                    'ip': ip,
                    'checked': 'No',
                    'threat_status': 'Unknown',
                    'last_checked': 'Never'
                }
                
                if db_row:
                    ip_info['checked'] = 'Yes'
                    ip_info['threat_status'] = 'Threat' if db_row['is_threat'] else 'Safe'
                    ip_info['last_checked'] = db_row['last_checked']
                    
                results.append(ip_info)
            
            conn.close()
        else:
            # No database yet, just return IPs with unknown status
            for ip in ip_list:
                results.append({
                    'ip': ip,
                    'checked': 'No',
                    'threat_status': 'Unknown',
                    'last_checked': 'Never'
                })
        
        return {
            'status': 'ok',
            'message': f'Found {len(results)} external IPs',
            'ips': results,
            'total_count': len(results)
        }
        
    except Exception as e:
        log_message(f"Error listing external IPs: {str(e)}")
        return {'status': 'error', 'message': f'Error listing external IPs: {str(e)}'}

def main():
    """Main entry point"""
    # First thing: log startup and ensure directories
    startup_message = "AbuseIPDBChecker script startup"
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {startup_message}", file=sys.stderr)
    system_log(startup_message)
    
    try:
        # Make sure required directories exist
        ensure_directories()
        
        # Now that directories exist, we can log properly
        log_message("Script started successfully")
        
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='AbuseIPDB Checker')
        parser.add_argument('mode', choices=[MODE_CHECK, MODE_STATS, MODE_THREATS, 'logs', 'testip', 'listips', 'debuglog', 'debugreal', 'daemon'],
                   help='Operation mode')
        parser.add_argument('ip', nargs='?', help='IP address to test (only for testip mode)')
        
        # Handle no arguments case - avoid crash
        if len(sys.argv) < 2:
            parser.print_help()
            log_message("Error: No operation mode specified")
            print(json.dumps({'status': 'error', 'message': 'No operation mode specified'}))
            return
            
        # Handle configd passing extra %s parameter
        filtered_args = [arg for arg in sys.argv[1:] if arg != '%s']
        args = parser.parse_args(filtered_args)
        log_message(f"Running in {args.mode} mode")
        
        # Different actions based on mode
        if args.mode == MODE_CHECK:
            log_message("Starting IP check operation")
            config = read_config()
            result = run_checker(config)
        elif args.mode == MODE_STATS:
            log_message("Retrieving statistics")
            result = get_statistics()
        elif args.mode == MODE_THREATS:
            log_message("Retrieving threats list")
            result = get_recent_threats()
        elif args.mode == 'logs':
            log_message("Retrieving logs")
            result = get_logs()
        elif args.mode == 'testip':
            if not args.ip:
                log_message("Error: No IP specified for test")
                result = {'status': 'error', 'message': 'IP address is required for testip mode'}
            else:
                log_message(f"Testing IP: {args.ip}")
                result = test_ip(args.ip)
        elif args.mode == 'listips':
            log_message("Listing external IPs from firewall logs")
            result = list_external_ips()
        elif args.mode == 'debuglog':
            log_message("Running debug log parsing")
            result = debug_log_parsing()
        elif args.mode == 'debugreal':
            log_message("Running real-time debug parsing")
            result = debug_real_parsing()
        elif args.mode == 'daemon':
            # Don't return JSON for daemon mode, just run
            log_message("Starting daemon mode")
            run_daemon()
            return
        else:
            # Should never get here due to argparse, but just in case
            log_message(f"Invalid mode: {args.mode}")
            result = {'status': 'error', 'message': f'Invalid mode: {args.mode}'}
        
        # Output result as JSON with no extra whitespace (not for daemon mode)
        output = json.dumps(result, separators=(',', ':'))
        print(output)
        log_message(f"Operation completed with status: {result.get('status', 'unknown')}")
        
    except Exception as e:
        error_msg = f"Unhandled exception in main: {str(e)}"
        system_log(error_msg)
        
        # Try to log to file even if it failed earlier
        try:
            log_message(error_msg)
        except:
            pass
            
        # Print JSON error for the UI to display
        print(json.dumps({'status': 'error', 'message': error_msg}, separators=(',', ':')))
        
        # Print error to stderr for daemon logs
        print(error_msg, file=sys.stderr)

if __name__ == '__main__':
    main()