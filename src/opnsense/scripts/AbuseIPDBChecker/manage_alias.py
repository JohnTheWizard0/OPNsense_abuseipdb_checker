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
    Alias Management Script for AbuseIPDB Checker
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

def classify_threat_level(abuse_score):
    """Classify threat level based on abuse score"""
    if abuse_score < 40:
        return 0  # Safe
    elif abuse_score < 70:
        return 1  # Suspicious
    else:
        return 2  # Malicious

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
            log_message(f"PHP stdout: {result.stdout[:200]}...")
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
    """Create MaliciousIPs alias with correct OPNsense structure"""
    try:
        config = read_config()
        if not config['alias_enabled']:
            return {'status': 'disabled', 'message': 'Alias integration is disabled'}
        
        log_message("Creating alias with CORRECT OPNsense structure")
        
        # Get threat IPs with proper newlines
        threat_ips = get_threat_ips_from_database(config)
        ip_content = '\n'.join(threat_ips) if threat_ips else '127.0.0.1'
        
        # Generate UUID
        alias_uuid = str(uuid_module.uuid4())
        log_message(f"Generated UUID: {alias_uuid}")
        
        php_script = f'''<?php
require_once '/usr/local/etc/inc/config.inc';
require_once '/usr/local/etc/inc/util.inc';

try {{
    $config = config_read_array();

    // Remove existing MaliciousIPs alias completely
    if (isset($config['aliases']['alias'])) {{
        foreach ($config['aliases']['alias'] as $index => $alias) {{
            if (isset($alias['name']) && $alias['name'] == 'MaliciousIPs') {{
                unset($config['aliases']['alias'][$index]);
                break;
            }}
        }}
        // Reindex array
        $config['aliases']['alias'] = array_values($config['aliases']['alias']);
    }}

    // Initialize if needed
    if (!isset($config['aliases']['alias'])) {{
        $config['aliases']['alias'] = array();
    }}

    // Create with PROPER structure (using content field like debug shows)
    $new_alias = array(
        'uuid' => '{alias_uuid}',
        'name' => 'MaliciousIPs',
        'type' => 'host',
        'content' => '{ip_content}',
        'description' => 'AbuseIPDB malicious IPs',
        'enabled' => '1'
    );

    $config['aliases']['alias'][] = $new_alias;

    // Save and reload
    write_config("AbuseIPDB: Created MaliciousIPs with UUID");
    configd_run('template reload OPNsense/Filter');
    configd_run('filter reload');

    echo "SUCCESS:{alias_uuid}";
}} catch (Exception $e) {{
    echo "ERROR:" . $e->getMessage();
    exit(1);
}}
?>'''
        
        result = execute_php_script(php_script)
        
        if result['exit_code'] == 0 and result['stdout'].startswith("SUCCESS:"):
            uuid = result['stdout'].split(":")[1].strip()
            log_message(f"Alias created successfully with UUID: {uuid}")
            return {
                'status': 'ok',
                'message': f'MaliciousIPs alias created with UUID and {len(threat_ips)} IPs',
                'uuid': uuid,
                'ip_count': len(threat_ips)
            }
        else:
            return {'status': 'error', 'message': f'Creation failed: {result["stderr"]}'}
                
    except Exception as e:
        error_msg = f"Error creating alias: {str(e)}"
        log_message(error_msg)
        return {'status': 'error', 'message': error_msg}

def update_alias():
    """Update MaliciousIPs alias"""
    try:
        config = read_config()
        if not config['alias_enabled']:
            return {'status': 'disabled', 'message': 'Alias integration is disabled'}
        
        log_message("Starting alias update")
        
        # Get current threat IPs
        threat_ips = get_threat_ips_from_database(config)
        ip_content = '\\n'.join(threat_ips) if threat_ips else ''
        
        php_script = f'''<?php
require_once '/usr/local/etc/inc/config.inc';
require_once '/usr/local/etc/inc/util.inc';

try {{
    $config = config_read_array();

    // Find the MaliciousIPs alias
    $alias_found = false;
    $alias_uuid = null;
    if (isset($config['aliases']['alias'])) {{
        foreach ($config['aliases']['alias'] as &$alias) {{
            if ($alias['name'] == 'MaliciousIPs') {{
                $alias['address'] = '{ip_content}';
                $alias['descr'] = 'Automatically maintained list of malicious IPs detected by AbuseIPDB Checker (Updated: ' . date('Y-m-d H:i:s') . ')';
                $alias_found = true;
                $alias_uuid = isset($alias['uuid']) ? $alias['uuid'] : 'unknown';
                break;
            }}
        }}
    }}

    if (!$alias_found) {{
        echo "NOT_FOUND";
        exit(1);
    }}

    // Save configuration
    write_config("AbuseIPDB Checker: Updated MaliciousIPs alias with {len(threat_ips)} IPs");

    // Reload aliases and firewall
    configd_run('template reload OPNsense/Filter');
    configd_run('filter reload');

    echo "UPDATED:$alias_uuid:{len(threat_ips)}";
}} catch (Exception $e) {{
    echo "ERROR:" . $e->getMessage();
    exit(1);
}}
?>'''
        
        result = execute_php_script(php_script)
        
        if result['exit_code'] == 0:
            output = result['stdout'].strip()
            if output == "NOT_FOUND":
                log_message("Alias not found, attempting to create it")
                return create_alias()
            elif output.startswith("UPDATED:"):
                parts = output.split(":")
                uuid = parts[1] if len(parts) > 1 else 'unknown'
                ip_count = parts[2] if len(parts) > 2 else len(threat_ips)
                log_message(f"Alias updated successfully: UUID={uuid}, IPs={ip_count}")
                return {
                    'status': 'ok',
                    'message': f'Alias updated with {ip_count} IPs',
                    'uuid': uuid,
                    'ip_count': int(ip_count)
                }
            else:
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
    """Test alias functionality"""
    try:
        log_message("Testing alias functionality")
        
        # First try to update (which will create if not exists)
        result = update_alias()
        log_message(f"Alias test result: {result['status']} - {result.get('message', 'No message')}")
        
        # Get current stats
        config = read_config()
        threat_count = len(get_threat_ips_from_database(config))
        
        result['test_info'] = {
            'config_enabled': config['alias_enabled'],
            'include_suspicious': config['alias_include_suspicious'],
            'max_hosts': config['alias_max_recent_hosts'],
            'current_threat_count': threat_count
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
        log_message(f"Alias management script started in {mode} mode")
        
        if mode == 'create':
            result = create_alias()
        elif mode == 'update':
            result = update_alias()
        elif mode == 'test':
            result = test_alias()
        else:
            result = {'status': 'error', 'message': f'Invalid mode: {mode}'}
        
        print(json.dumps(result, separators=(',', ':')))
        log_message(f"Alias operation completed: {result['status']}")
        
    except Exception as e:
        error_result = {'status': 'error', 'message': f'Script error: {str(e)}'}
        print(json.dumps(error_result, separators=(',', ':')))
        log_message(f"Script error: {str(e)}")

if __name__ == '__main__':
    main()
