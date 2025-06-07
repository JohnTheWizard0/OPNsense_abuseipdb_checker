#!/usr/local/bin/python3

import subprocess
import tempfile
import json
import uuid as uuid_module
import sys

def execute_php_script(php_code):
    """Execute PHP code and return result"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
            f.write(php_code)
            php_file = f.name
        
        result = subprocess.run(['/usr/local/bin/php', php_file], capture_output=True, text=True)
        return {
            'exit_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
    except Exception as e:
        return {'exit_code': 1, 'stdout': '', 'stderr': str(e)}

def test_minimal_alias(test_name, alias_structure):
    """Test creating alias with specific structure"""
    print(f"\n=== TESTING: {test_name} ===")
    
    alias_uuid = str(uuid_module.uuid4())
    
    # Convert structure to PHP array format
    php_fields = []
    for key, value in alias_structure.items():
        if key == 'uuid':
            value = alias_uuid
        php_fields.append(f"'{key}' => '{value}'")
    
    php_array = "array(\n        " + ",\n        ".join(php_fields) + "\n    )"
    
    php_script = f'''<?php
require_once '/usr/local/etc/inc/config.inc';
require_once '/usr/local/etc/inc/util.inc';

try {{
    $config = config_read_array();

    // Remove any existing test aliases
    if (isset($config['aliases']['alias'])) {{
        foreach ($config['aliases']['alias'] as $index => $alias) {{
            if (isset($alias['name']) && (
                $alias['name'] == 'TestAlias' || 
                $alias['name'] == 'MaliciousIPs'
            )) {{
                unset($config['aliases']['alias'][$index]);
            }}
        }}
        $config['aliases']['alias'] = array_values($config['aliases']['alias']);
    }}

    // Initialize if needed
    if (!isset($config['aliases']['alias'])) {{
        $config['aliases']['alias'] = array();
    }}

    // Create test alias
    $test_alias = {php_array};
    $config['aliases']['alias'][] = $test_alias;

    // Save configuration
    write_config("Test alias creation: {test_name}");
    
    // Multiple reload strategies
    configd_run('template reload OPNsense/Filter');
    sleep(1);
    configd_run('filter reload');
    sleep(1);
    configd_run('filter configure');

    // Verify creation
    $verify_config = config_read_array();
    $found = false;
    $found_structure = null;
    
    if (isset($verify_config['aliases']['alias'])) {{
        foreach ($verify_config['aliases']['alias'] as $alias) {{
            if (isset($alias['name']) && $alias['name'] == 'TestAlias') {{
                $found = true;
                $found_structure = $alias;
                break;
            }}
        }}
    }}

    if ($found) {{
        echo "VERIFIED\\n";
        echo "Structure: " . json_encode($found_structure, JSON_PRETTY_PRINT) . "\\n";
    }} else {{
        echo "NOT_FOUND\\n";
    }}

    echo "UUID: {alias_uuid}\\n";

}} catch (Exception $e) {{
    echo "ERROR: " . $e->getMessage() . "\\n";
    exit(1);
}}
?>'''
    
    result = execute_php_script(php_script)
    print(f"Exit Code: {result['exit_code']}")
    print(f"Output:\n{result['stdout']}")
    if result['stderr']:
        print(f"Errors:\n{result['stderr']}")
    
    return result['exit_code'] == 0 and 'VERIFIED' in result['stdout']

def main():
    """Run comprehensive alias structure tests"""
    
    print("=== MINIMAL ALIAS STRUCTURE TESTING ===")
    print("Testing different alias structures to find what works in WebUI...")
    
    # Test 1: Absolute minimal structure
    test1_result = test_minimal_alias("MINIMAL", {
        'name': 'TestAlias',
        'type': 'host',
        'content': '1.1.1.1'
    })
    
    # Test 2: With UUID
    test2_result = test_minimal_alias("WITH_UUID", {
        'uuid': 'placeholder',
        'name': 'TestAlias',
        'type': 'host',
        'content': '1.1.1.1'
    })
    
    # Test 3: With enabled field
    test3_result = test_minimal_alias("WITH_ENABLED", {
        'uuid': 'placeholder',
        'name': 'TestAlias',
        'type': 'host',
        'content': '1.1.1.1',
        'enabled': '1'
    })
    
    # Test 4: With description
    test4_result = test_minimal_alias("WITH_DESC", {
        'uuid': 'placeholder',
        'name': 'TestAlias',
        'type': 'host',
        'content': '1.1.1.1',
        'enabled': '1',
        'description': 'Test alias'
    })
    
    # Test 5: Legacy address field instead of content
    test5_result = test_minimal_alias("LEGACY_ADDRESS", {
        'uuid': 'placeholder',
        'name': 'TestAlias',
        'type': 'host',
        'address': '1.1.1.1',
        'enabled': '1',
        'description': 'Test alias'
    })
    
    # Test 6: Both address and content (like current issue)
    test6_result = test_minimal_alias("BOTH_FIELDS", {
        'uuid': 'placeholder',
        'name': 'TestAlias',
        'type': 'host',
        'address': '1.1.1.1',
        'content': '1.1.1.1',
        'enabled': '1',
        'description': 'Test alias'
    })
    
    # Test 7: Full OPNsense structure
    test7_result = test_minimal_alias("FULL_STRUCTURE", {
        'uuid': 'placeholder',
        'name': 'TestAlias',
        'type': 'host',
        'proto': '',
        'interface': '',
        'address': '',
        'content': '1.1.1.1',
        'descr': 'Test alias',
        'detail': '',
        'enabled': '1'
    })
    
    print("\n=== TEST RESULTS SUMMARY ===")
    tests = [
        ("Minimal", test1_result),
        ("With UUID", test2_result),
        ("With Enabled", test3_result),
        ("With Description", test4_result),
        ("Legacy Address", test5_result),
        ("Both Fields", test6_result),
        ("Full Structure", test7_result)
    ]
    
    for test_name, result in tests:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name:15} {status}")
    
    print(f"\n=== NEXT STEPS ===")
    if any(result for _, result in tests):
        print("✓ At least one structure worked - check WebUI now")
        print("  Navigate to Firewall -> Aliases")
        print("  Look for 'TestAlias' entry")
        print("  Note which structure appears correctly")
    else:
        print("✗ No structures worked - deeper issue detected")
        print("  May need to check OPNsense logs: /var/log/system.log")
        print("  Consider manual alias creation in WebUI for comparison")
    
    print("\n=== MANUAL VERIFICATION COMMANDS ===")
    print("# Check current aliases in config:")
    print("configctl abuseipdbchecker debugalias")
    print("\n# Check OPNsense system logs:")
    print("tail -50 /var/log/system.log | grep -i alias")
    print("\n# Force WebUI cache clear:")
    print("/usr/local/etc/rc.restart_webgui")

if __name__ == '__main__':
    main()
