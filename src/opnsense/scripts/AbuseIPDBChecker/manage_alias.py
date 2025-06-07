#!/usr/local/bin/python3

"""
CORRECTED Alias Management Script for AbuseIPDB Checker
Using the proper OPNsense alias structure discovered from WebGUI export
"""

import os
import sys
import json
import sqlite3
import uuid as uuid_module
import subprocess
import tempfile
from datetime import datetime
from configparser import ConfigParser

# Constants
DB_DIR = '/var/db/abuseipdbchecker'
DB_FILE = os.path.join(DB_DIR, 'abuseipdb.db')
CONFIG_FILE = '/usr/local/etc/abuseipdbchecker/abuseipdbchecker.conf'
LOG_DIR = '/var/log/abuseipdbchecker'
LOG_FILE = os.path.join(LOG_DIR, 'abuseipdb.log')

def log_message(message):
    """Log a message to the log file"""
    try:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR, mode=0o755)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(LOG_FILE, 'a') as f:
            f.write(f"[{timestamp}] ALIAS: {message}\n")
        
        os.chmod(LOG_FILE, 0o666)
    except Exception as e:
        print(f"Error writing to log: {str(e)}", file=sys.stderr)

def read_config():
    """Read configuration from OPNsense config file"""
    config = {
        'alias_enabled': True,
        'alias_include_suspicious': False,
        'alias_max_recent_hosts': 500
    }
    
    if os.path.exists(CONFIG_FILE):
        try:
            cp = ConfigParser()
            cp.read(CONFIG_FILE)
            
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
        
        log_message(f"Querying threats with min_level={min_threat_level}, max_hosts={max_hosts}")
        
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

def execute_php_script(php_code):
    """Execute PHP code and return result"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
            f.write(php_code)
            php_file = f.name
        
        try:
            result = subprocess.run([
                '/usr/local/bin/php', php_file
            ], capture_output=True, text=True, timeout=30)
            
            log_message(f"PHP execution: exit_code={result.returncode}")
            if result.stderr:
                log_message(f"PHP stderr: {result.stderr[:200]}...")
            
            return {
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
                
        finally:
            try:
                os.unlink(php_file)
            except:
                pass
                
    except Exception as e:
        log_message(f"Error executing PHP script: {str(e)}")
        return {
            'exit_code': 1,
            'stdout': '',
            'stderr': str(e)
        }

def create_alias():
    """Create MaliciousIPs alias with CORRECT OPNsense structure"""
    try:
        config = read_config()
        if not config['alias_enabled']:
            return {'status': 'disabled', 'message': 'Alias integration is disabled'}
        
        log_message("Creating alias with CORRECT OPNsense structure")
        
        # Get threat IPs
        threat_ips = get_threat_ips_from_database(config)
        ip_content = '\\n'.join(threat_ips) if threat_ips else '127.0.0.1'
        
        # Generate UUID for the alias
        alias_uuid = str(uuid_module.uuid4())
        current_timestamp = datetime.now().isoformat()
        
        log_message(f"Generated UUID: {alias_uuid}")
        log_message(f"IP content length: {len(ip_content)} chars, {len(threat_ips)} IPs")
        
        php_script = f'''<?php
require_once '/usr/local/etc/inc/config.inc';
require_once '/usr/local/etc/inc/util.inc';

try {{
    $config = config_read_array();

    // Remove any existing MaliciousIPs alias first
    if (isset($config['aliases']['alias'])) {{
        foreach ($config['aliases']['alias'] as $uuid => $alias) {{
            if (isset($alias['name']) && $alias['name'] == 'MaliciousIPs') {{
                unset($config['aliases']['alias'][$uuid]);
                echo "REMOVED_EXISTING: $uuid\\n";
            }}
        }}
    }}

    // Initialize aliases section if needed
    if (!isset($config['aliases']['alias'])) {{
        $config['aliases']['alias'] = array();
    }}

    // Create with PROPER OPNsense structure (UUID as KEY, not field)
    $alias_uuid = '{alias_uuid}';
    $config['aliases']['alias'][$alias_uuid] = array(
        'enabled' => '1',
        'name' => 'MaliciousIPs',
        'type' => 'host',
        'path_expression' => '',
        'proto' => '',
        'interface' => '',
        'counters' => '0',
        'updatefreq' => '',
        'content' => '{ip_content}',
        'password' => '',
        'username' => '',
        'authtype' => '',
        'categories' => '',
        'current_items' => '{len(threat_ips)}',
        'last_updated' => '{current_timestamp}',
        'description' => 'AbuseIPDB malicious IPs (auto-managed)'
    );

    // Save configuration
    write_config("AbuseIPDB: Created proper MaliciousIPs alias with {len(threat_ips)} IPs");

    // Reload configuration
    configd_run('template reload OPNsense/Filter');
    sleep(1);
    configd_run('filter reload');

    echo "SUCCESS:$alias_uuid:{len(threat_ips)}\\n";

}} catch (Exception $e) {{
    echo "ERROR:" . $e->getMessage() . "\\n";
    exit(1);
}}
?>'''
        
        result = execute_php_script(php_script)
        
        # FIX: Check if SUCCESS appears ANYWHERE in stdout, not just at start
        if result['exit_code'] == 0 and "SUCCESS:" in result['stdout']:
            # Extract the SUCCESS line specifically
            success_line = ""
            for line in result['stdout'].split('\n'):
                if line.startswith("SUCCESS:"):
                    success_line = line
                    break
            
            if success_line:
                parts = success_line.strip().split(":")
                uuid = parts[1] if len(parts) > 1 else alias_uuid
                ip_count = parts[2] if len(parts) > 2 else len(threat_ips)
                
                log_message(f"Alias created successfully with UUID: {uuid}")
                return {
                    'status': 'ok',
                    'message': f'MaliciousIPs alias created with proper structure and {ip_count} IPs',
                    'uuid': uuid,
                    'ip_count': int(ip_count)
                }
        
        # If we get here, there was an error
        error_msg = f'Creation failed: {result["stderr"]} | {result["stdout"]}'
        log_message(error_msg)
        return {'status': 'error', 'message': error_msg}
                
    except Exception as e:
        error_msg = f"Error creating alias: {str(e)}"
        log_message(error_msg)
        return {'status': 'error', 'message': error_msg}

def update_alias():
    """Update MaliciousIPs alias with proper structure"""
    try:
        config = read_config()
        if not config['alias_enabled']:
            return {'status': 'disabled', 'message': 'Alias integration is disabled'}
        
        log_message("Starting alias update with proper structure")
        
        # Get current threat IPs
        threat_ips = get_threat_ips_from_database(config)
        ip_content = '\\n'.join(threat_ips) if threat_ips else ''
        current_timestamp = datetime.now().isoformat()
        
        php_script = f'''<?php
require_once '/usr/local/etc/inc/config.inc';
require_once '/usr/local/etc/inc/util.inc';

try {{
    $config = config_read_array();

    // Find the MaliciousIPs alias (UUID as key)
    $alias_found = false;
    $alias_uuid = null;
    
    if (isset($config['aliases']['alias'])) {{
        foreach ($config['aliases']['alias'] as $uuid => $alias) {{
            if (isset($alias['name']) && $alias['name'] == 'MaliciousIPs') {{
                // Update with proper structure
                $config['aliases']['alias'][$uuid]['content'] = '{ip_content}';
                $config['aliases']['alias'][$uuid]['current_items'] = '{len(threat_ips)}';
                $config['aliases']['alias'][$uuid]['last_updated'] = '{current_timestamp}';
                $config['aliases']['alias'][$uuid]['description'] = 'AbuseIPDB malicious IPs (Updated: ' . date('Y-m-d H:i:s') . ')';
                
                $alias_found = true;
                $alias_uuid = $uuid;
                break;
            }}
        }}
    }}

    if (!$alias_found) {{
        echo "NOT_FOUND\\n";
        exit(1);
    }}

    // Save configuration
    write_config("AbuseIPDB: Updated MaliciousIPs alias with {len(threat_ips)} IPs");

    // Reload configuration
    configd_run('template reload OPNsense/Filter');
    configd_run('filter reload');

    echo "UPDATED:$alias_uuid:{len(threat_ips)}\\n";

}} catch (Exception $e) {{
    echo "ERROR:" . $e->getMessage() . "\\n";
    exit(1);
}}
?>'''
        
        result = execute_php_script(php_script)
        
        if result['exit_code'] == 0:
            output = result['stdout'].strip()
            
            # Check for NOT_FOUND anywhere in output
            if "NOT_FOUND" in output:
                log_message("Alias not found, creating new one")
                return create_alias()
            # Check for UPDATED anywhere in output  
            elif "UPDATED:" in output:
                # Extract the UPDATED line specifically
                for line in output.split('\n'):
                    if line.startswith("UPDATED:"):
                        parts = line.split(":")
                        uuid = parts[1] if len(parts) > 1 else 'unknown'
                        ip_count = parts[2] if len(parts) > 2 else len(threat_ips)
                        log_message(f"Alias updated successfully: UUID={uuid}, IPs={ip_count}")
                        return {
                            'status': 'ok',
                            'message': f'Alias updated with proper structure and {ip_count} IPs',
                            'uuid': uuid,
                            'ip_count': int(ip_count)
                        }
            
            log_message(f"Unexpected PHP output: {output}")
            return {'status': 'error', 'message': f'Unexpected output: {output}'}
        else:
            error_msg = f"PHP script failed: {result['stderr']}"
            log_message(error_msg)
            return {'status': 'error', 'message': error_msg}
                
    except Exception as e:
        error_msg = f"Error updating alias: {str(e)}"
        log_message(error_msg)
        return {'status': 'error', 'message': error_msg}

def test_alias():
    """Test alias functionality with proper structure"""
    try:
        log_message("Testing alias functionality with proper structure")
        
        result = update_alias()
        log_message(f"Alias test result: {result['status']} - {result.get('message', 'No message')}")
        
        # Get current stats
        config = read_config()
        threat_count = len(get_threat_ips_from_database(config))
        
        result['test_info'] = {
            'config_enabled': config['alias_enabled'],
            'include_suspicious': config['alias_include_suspicious'],
            'max_hosts': config['alias_max_recent_hosts'],
            'current_threat_count': threat_count,
            'structure': 'CORRECTED - UUID as key with all required fields'
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
        log_message(f"CORRECTED alias management script started in {mode} mode")
        
        if mode == 'create':
            result = create_alias()
        elif mode == 'update':
            result = update_alias()
        elif mode == 'test':
            result = test_alias()
        else:
            result = {'status': 'error', 'message': f'Invalid mode: {mode}'}
        
        print(json.dumps(result, separators=(',', ':')))
        log_message(f"CORRECTED alias operation completed: {result['status']}")
        
    except Exception as e:
        error_result = {'status': 'error', 'message': f'Script error: {str(e)}'}
        print(json.dumps(error_result, separators=(',', ':')))
        log_message(f"Script error: {str(e)}")

if __name__ == '__main__':
    main()