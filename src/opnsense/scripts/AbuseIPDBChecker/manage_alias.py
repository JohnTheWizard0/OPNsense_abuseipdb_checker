#!/usr/local/bin/python3

"""
REST API-based Alias Management Script for AbuseIPDB Checker
Using OPNsense REST API instead of direct config manipulation
"""

import os
import sys
import json
import sqlite3
import requests
import urllib3
from datetime import datetime, timedelta, timezone
from configparser import ConfigParser

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
DB_DIR = '/var/db/abuseipdbchecker'
DB_FILE = os.path.join(DB_DIR, 'abuseipdb.db')
CONFIG_FILE = '/usr/local/etc/abuseipdbchecker/abuseipdbchecker.conf'
LOG_DIR = '/var/log/abuseipdbchecker'
LOG_FILE = os.path.join(LOG_DIR, 'abuseipdb.log')

def get_system_timezone():
    """Get the system's local timezone safely"""
    try:
        # Try to get system timezone using datetime
        local_dt = datetime.now().astimezone()
        return local_dt.tzinfo
    except Exception:
        try:
            # Fallback: use time module
            import time
            if time.daylight:
                # DST is in effect, use the DST offset
                offset_seconds = -time.altzone
            else:
                # Standard time
                offset_seconds = -time.timezone
            
            offset_hours = offset_seconds // 3600
            offset_minutes = (abs(offset_seconds) % 3600) // 60
            
            return timezone(timedelta(hours=offset_hours, minutes=offset_minutes))
        except Exception:
            # Final fallback to UTC
            return timezone.utc

# Get system timezone on module load
LOCAL_TZ = get_system_timezone()

def get_local_time():
    """Get current time in system's local timezone"""
    return datetime.now(LOCAL_TZ)

def format_timestamp(dt=None):
    """Format timestamp in local timezone WITHOUT timezone abbreviation"""
    if dt is None:
        dt = get_local_time()
    elif isinstance(dt, str):
        try:
            if dt.endswith('Z'):
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            elif '+' in dt or dt.count('-') > 2:
                dt = datetime.fromisoformat(dt)
            else:
                dt = datetime.fromisoformat(dt)
                dt = dt.replace(tzinfo=LOCAL_TZ)
            dt = dt.astimezone(LOCAL_TZ)
        except Exception:
            return dt
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc).astimezone(LOCAL_TZ)
    elif dt.tzinfo != LOCAL_TZ:
        dt = dt.astimezone(LOCAL_TZ)
    
    # Format WITHOUT timezone abbreviation - matches core_utils.py
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def log_message(message):
    """Log a message to the log file with proper timezone"""
    try:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR, mode=0o755)
        
        timestamp = format_timestamp()
        with open(LOG_FILE, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
        
        os.chmod(LOG_FILE, 0o666)
    except Exception as e:
        print(f"Error writing to log: {str(e)}", file=sys.stderr)

def read_config():
    """Read configuration from OPNsense config file"""
    config = {
        'alias_enabled': True,
        'alias_include_suspicious': False,
        'alias_max_recent_hosts': 500,
        'api_key': '',
        'api_secret': ''
    }
    
    if os.path.exists(CONFIG_FILE):
        try:
            cp = ConfigParser()
            cp.read(CONFIG_FILE)
            
            if cp.has_section('general'):
                if cp.has_option('general', 'ApiKey'):
                    config['api_key'] = cp.get('general', 'ApiKey')
                if cp.has_option('general', 'ApiSecret'):
                    config['api_secret'] = cp.get('general', 'ApiSecret')
            
            if cp.has_section('alias'):
                if cp.has_option('alias', 'Enabled'):
                    config['alias_enabled'] = cp.get('alias', 'Enabled') == '1'
                if cp.has_option('alias', 'IncludeSuspicious'):
                    config['alias_include_suspicious'] = cp.get('alias', 'IncludeSuspicious') == '1'
                if cp.has_option('alias', 'MaxRecentHosts'):
                    config['alias_max_recent_hosts'] = int(cp.get('alias', 'MaxRecentHosts'))
        except Exception as e:
            log_message(f"Error reading config: {str(e)}")
    
    return config

def get_threat_ips_from_database(config):
    """Get threat IPs from database based on configuration"""
    threat_ips = []
    
    if not os.path.exists(DB_FILE):
        log_message("Database file not found")
        return threat_ips
    
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Build query based on configuration
        min_threat_level = 1 if config['alias_include_suspicious'] else 2
        max_hosts = config['alias_max_recent_hosts']
        
        c.execute('''
        SELECT t.ip, t.abuse_score
        FROM threats t
        JOIN checked_ips ci ON t.ip = ci.ip
        WHERE ci.threat_level >= ?
        ORDER BY 
            t.abuse_score DESC,
            ci.last_checked DESC
        LIMIT ?
        ''', (min_threat_level, max_hosts))
        
        for row in c.fetchall():
            threat_ips.append(row['ip'])
        
        conn.close()
        log_message(f"Retrieved {len(threat_ips)} threat IPs from database")
        
    except Exception as e:
        log_message(f"Error getting threat IPs from database: {str(e)}")
    
    return threat_ips

def make_api_request(method, endpoint, config, data=None):
    """Make a request to OPNsense API - REDUCED LOGGING"""
    base_url = "https://127.0.0.1"
    url = f"{base_url}{endpoint}"
    
    auth = (config['api_key'], config['api_secret'])
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, auth=auth, verify=False, timeout=30)
        elif method.upper() == 'POST':
            if data is None:
                # For reconfigure calls - no JSON data needed
                response = requests.post(url, auth=auth, verify=False, timeout=30)
            else:
                # For data calls - send JSON
                headers = {'Content-Type': 'application/json'}
                response = requests.post(url, auth=auth, headers=headers, json=data, verify=False, timeout=30)
        elif method.upper() == 'PUT':
            headers = {'Content-Type': 'application/json'}
            response = requests.put(url, auth=auth, headers=headers, json=data, verify=False, timeout=30)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, auth=auth, verify=False, timeout=30)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        # REMOVED VERBOSE API LOGGING - only log errors
        if response.status_code not in [200, 201]:
            log_message(f"API {method} {endpoint}: HTTP {response.status_code} - {response.text}")
        
        if response.status_code in [200, 201]:
            return {'status': 'ok', 'data': response.json()}
        else:
            return {'status': 'error', 'message': f'HTTP {response.status_code}: {response.text}'}
            
    except requests.exceptions.RequestException as e:
        return {'status': 'error', 'message': f'Request failed: {str(e)}'}
    except Exception as e:
        return {'status': 'error', 'message': f'API error: {str(e)}'}

def find_malicious_ips_alias(config):
    """Find existing MaliciousIPs alias"""
    try:
        result = make_api_request('GET', '/api/firewall/alias/searchItem', config)
        
        if result['status'] != 'ok':
            return None
            
        # Search through aliases for MaliciousIPs
        aliases = result['data'].get('rows', [])
        for alias in aliases:
            if alias.get('name') == 'MaliciousIPs':
                return alias.get('uuid')
        
        return None
        
    except Exception as e:
        log_message(f"Error finding alias: {str(e)}")
        return None

def create_alias(config, threat_ips):
    """Create MaliciousIPs alias using REST API"""
    try:
        alias_data = {
            "alias": {
                "enabled": "1",
                "name": "MaliciousIPs",
                "type": "host",
                "content": "\n".join(threat_ips) if threat_ips else "127.0.0.1",
                "description": f"AbuseIPDB malicious IPs"
            }
        }
        
        log_message(f"Creating MaliciousIPs alias with {len(threat_ips)} IPs")
        
        # Create the alias
        result = make_api_request('POST', '/api/firewall/alias/addItem', config, alias_data)
        
        if result['status'] != 'ok':
            return result
        
        # Reconfigure firewall to apply changes
        reconfig_result = make_api_request('POST', '/api/firewall/alias/reconfigure', config, data=None)
        
        if reconfig_result['status'] != 'ok':
            return {'status': 'error', 'message': f'Alias created but reconfigure failed: {reconfig_result["message"]}'}
        
        log_message(f"✓ MaliciousIPs alias created and applied: {len(threat_ips)} IPs")
        
        return {
            'status': 'ok',
            'message': f'MaliciousIPs alias created with {len(threat_ips)} IPs',
            'uuid': result['data'].get('uuid', 'unknown'),
            'ip_count': len(threat_ips)
        }
        
    except Exception as e:
        error_msg = f"Error creating alias: {str(e)}"
        log_message(error_msg)
        return {'status': 'error', 'message': error_msg}

def update_alias(config, threat_ips):
    """Update existing MaliciousIPs alias using REST API"""
    try:
        # Find existing alias
        alias_uuid = find_malicious_ips_alias(config)
        
        if not alias_uuid:
            log_message("MaliciousIPs alias not found, creating new one")
            return create_alias(config, threat_ips)
        
        alias_data = {
            "alias": {
                "enabled": "1",
                "name": "MaliciousIPs",
                "type": "host", 
                "content": "\n".join(threat_ips) if threat_ips else "127.0.0.1",
                "description": f"AbuseIPDB malicious IPs - {len(threat_ips)} IPs (Updated: {format_timestamp()})"
            }
        }
        
        # Update the alias
        result = make_api_request('POST', f'/api/firewall/alias/setItem/{alias_uuid}', config, alias_data)
        
        if result['status'] != 'ok':
            return result
        
        # Reconfigure firewall to apply changes
        reconfig_result = make_api_request('POST', '/api/firewall/alias/reconfigure', config, data=None)
        
        if reconfig_result['status'] != 'ok':
            return {'status': 'error', 'message': f'Alias updated but reconfigure failed: {reconfig_result["message"]}'}
        
        log_message(f"✓ MaliciousIPs alias updated and applied: {len(threat_ips)} IPs")
        
        return {
            'status': 'ok',
            'message': f'Alias updated with {len(threat_ips)} IPs',
            'uuid': alias_uuid,
            'ip_count': len(threat_ips)
        }
        
    except Exception as e:
        error_msg = f"Error updating alias: {str(e)}"
        log_message(error_msg)
        return {'status': 'error', 'message': error_msg}

def create_alias_main():
    """Create MaliciousIPs alias"""
    try:
        config = read_config()
        
        if not config['alias_enabled']:
            return {'status': 'disabled', 'message': 'Alias integration is disabled'}
        
        if not config['api_key'] or not config['api_secret']:
            return {'status': 'error', 'message': 'API credentials not configured. Please set API key and secret in General settings.'}
        
        threat_ips = get_threat_ips_from_database(config)
        return create_alias(config, threat_ips)
        
    except Exception as e:
        error_msg = f"Error in create_alias_main: {str(e)}"
        log_message(error_msg)
        return {'status': 'error', 'message': error_msg}

def update_alias_main():
    """Update MaliciousIPs alias"""
    try:
        config = read_config()
        
        if not config['alias_enabled']:
            return {'status': 'disabled', 'message': 'Alias integration is disabled'}
        
        if not config['api_key'] or not config['api_secret']:
            return {'status': 'error', 'message': 'API credentials not configured. Please set API key and secret in General settings.'}
        
        threat_ips = get_threat_ips_from_database(config)
        return update_alias(config, threat_ips)
        
    except Exception as e:
        error_msg = f"Error in update_alias_main: {str(e)}"
        log_message(error_msg)
        return {'status': 'error', 'message': error_msg}

def test_alias():
    """Test alias functionality"""
    try:
        config = read_config()
        
        if not config['alias_enabled']:
            return {'status': 'disabled', 'message': 'Alias integration is disabled'}
        
        if not config['api_key'] or not config['api_secret']:
            return {'status': 'error', 'message': 'API credentials not configured'}
        
        # Test API connectivity
        test_result = make_api_request('GET', '/api/firewall/alias/searchItem', config)
        
        if test_result['status'] != 'ok':
            return {'status': 'error', 'message': f'API test failed: {test_result["message"]}'}
        
        # Try to update alias
        result = update_alias_main()
        
        # Get current stats
        threat_count = len(get_threat_ips_from_database(config))
        
        result['test_info'] = {
            'api_connection': 'OK',
            'config_enabled': config['alias_enabled'],
            'include_suspicious': config['alias_include_suspicious'],
            'max_hosts': config['alias_max_recent_hosts'],
            'current_threat_count': threat_count,
            'method': 'REST API'
        }
        
        return result
        
    except Exception as e:
        error_msg = f"Error testing alias: {str(e)}"
        log_message(error_msg)
        return {'status': 'error', 'message': error_msg}

def main():
    """Main entry point"""
    try:
        if len(sys.argv) < 2:
            return {'status': 'error', 'message': 'Mode required: create, update, or test'}
        
        mode = sys.argv[1].lower()
        
        if mode == 'create':
            result = create_alias_main()
        elif mode == 'update':
            result = update_alias_main()
        elif mode == 'test':
            result = test_alias()
        else:
            result = {'status': 'error', 'message': f'Invalid mode: {mode}'}
        
        print(json.dumps(result, separators=(',', ':')))
        
    except Exception as e:
        error_result = {'status': 'error', 'message': f'Script error: {str(e)}'}
        print(json.dumps(error_result, separators=(',', ':')))
        log_message(f"Alias management error: {str(e)}")

if __name__ == '__main__':
    main()