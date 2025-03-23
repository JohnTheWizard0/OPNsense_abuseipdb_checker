<?php

/**
 * AbuseIPDBChecker service integration
 */

function abuseipdbchecker_services() {
    global $config;
    
    $services = array();
    
    // Debug output - helps see what's in config
    syslog(LOG_NOTICE, "AbuseIPDBChecker: Config check - " . 
        (isset($config['OPNsense']['abuseipdbchecker']['general']['Enabled']) ? 
        "Enabled found: " . $config['OPNsense']['abuseipdbchecker']['general']['Enabled'] : 
        "Enabled not found"));
    
    // Force-enable for testing
    $service = array();
    $service['name'] = 'abuseipdbchecker';
    $service['description'] = gettext('AbuseIPDB Checker');
    $service['configd']['restart'] = array('abuseipdbchecker restart');
    $service['configd']['start'] = array('abuseipdbchecker start');
    $service['configd']['stop'] = array('abuseipdbchecker stop');
    $service['configd']['status'] = array('abuseipdbchecker status');
    
    $services[] = $service;
    
    return $services;
}

// Add configure function for bootup integration
function abuseipdbchecker_configure() {
    return array(
        'bootup' => array('abuseipdbchecker_setup')
    );
}

// Setup function that runs at boot
function abuseipdbchecker_setup() {
    // Ensure service directories exist
    mwexec("mkdir -p /var/log/abuseipdbchecker");
    mwexec("mkdir -p /var/db/abuseipdbchecker");
    mwexec("chmod -R 755 /var/log/abuseipdbchecker");
    mwexec("chmod -R 755 /var/db/abuseipdbchecker");
    
    // Initialize DB if needed
    if (!file_exists('/var/db/abuseipdbchecker/abuseipdb.db')) {
        mwexec("/usr/local/opnsense/scripts/AbuseIPDBChecker/setup_database.py");
    }
    
    return true;
}

function abuseipdbchecker_xmlrpc_sync() {
    $result = array();
    $result[] = array(
        'description' => gettext('AbuseIPDB Checker'),
        'section' => 'OPNsense.abuseipdbchecker',
        'id' => 'abuseipdbchecker',
        'services' => 'abuseipdbchecker'
    );
    return $result;
}