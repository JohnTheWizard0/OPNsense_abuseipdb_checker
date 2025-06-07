#!/usr/local/bin/python3

import subprocess
import tempfile
import json

def execute_php_debug():
    """Debug what's actually in the config"""
    php_script = '''<?php
require_once '/usr/local/etc/inc/config.inc';

try {
    $config = config_read_array();
    
    echo "=== ALIAS SECTION DEBUG ===\\n";
    
    if (isset($config['aliases'])) {
        echo "Aliases section exists\\n";
        if (isset($config['aliases']['alias'])) {
            echo "Alias array exists with " . count($config['aliases']['alias']) . " entries\\n";
            
            foreach ($config['aliases']['alias'] as $index => $alias) {
                echo "\\nAlias $index:\\n";
                echo "  Name: " . (isset($alias['name']) ? $alias['name'] : 'NOT SET') . "\\n";
                echo "  Type: " . (isset($alias['type']) ? $alias['type'] : 'NOT SET') . "\\n";
                echo "  UUID: " . (isset($alias['uuid']) ? $alias['uuid'] : 'NOT SET') . "\\n";
                echo "  Enabled: " . (isset($alias['enabled']) ? $alias['enabled'] : 'NOT SET') . "\\n";
                echo "  Address: " . (isset($alias['address']) ? substr($alias['address'], 0, 100) . '...' : 'NOT SET') . "\\n";
                
                if (isset($alias['name']) && $alias['name'] == 'MaliciousIPs') {
                    echo "  *** FOUND MaliciousIPs ALIAS ***\\n";
                    echo "  Full structure: " . print_r($alias, true) . "\\n";
                }
            }
        } else {
            echo "No alias array found\\n";
        }
    } else {
        echo "No aliases section found\\n";
    }
    
    echo "\\n=== SEARCHING FOR MaliciousIPs ===\\n";
    $found = false;
    if (isset($config['aliases']['alias'])) {
        foreach ($config['aliases']['alias'] as $alias) {
            if (isset($alias['name']) && $alias['name'] == 'MaliciousIPs') {
                echo "FOUND: " . json_encode($alias, JSON_PRETTY_PRINT) . "\\n";
                $found = true;
            }
        }
    }
    
    if (!$found) {
        echo "MaliciousIPs alias NOT FOUND in config\\n";
    }
    
} catch (Exception $e) {
    echo "ERROR: " . $e->getMessage() . "\\n";
}
?>'''
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
            f.write(php_script)
            php_file = f.name
        
        result = subprocess.run(['/usr/local/bin/php', php_file], capture_output=True, text=True)
        print("=== CONFIG DEBUG OUTPUT ===")
        print(result.stdout)
        if result.stderr:
            print("=== ERRORS ===")
            print(result.stderr)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    execute_php_debug()
