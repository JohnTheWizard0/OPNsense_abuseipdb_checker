<?php

function abuseipdbchecker_services() {
    $services = array();
    
    $service = array();
    $service['name'] = 'abuseipdbchecker';
    $service['description'] = gettext('AbuseIPDB Checker');
    
    // Critical: These must match configd action names exactly
    $service['configd']['restart'] = array('abuseipdbchecker restart');
    $service['configd']['start'] = array('abuseipdbchecker start');
    $service['configd']['stop'] = array('abuseipdbchecker stop');
    
    // This is the key for status display
    $service['pidfile'] = '/var/run/abuseipdbchecker.pid';
    
    $services[] = $service;
    return $services;
}

function abuseipdbchecker_configure() {
    return array(
        'bootup' => array('abuseipdbchecker_setup')
    );
}

function abuseipdbchecker_setup() {
    mwexec("mkdir -p /var/log/abuseipdbchecker");
    mwexec("mkdir -p /var/db/abuseipdbchecker");
    mwexec("chmod -R 777 /var/log/abuseipdbchecker");
    mwexec("chmod -R 777 /var/db/abuseipdbchecker");
    
    if (!file_exists('/var/db/abuseipdbchecker/abuseipdb.db')) {
        mwexec("/usr/local/opnsense/scripts/AbuseIPDBChecker/setup_database.py");
    }
    
    // Create MaliciousIPs alias using new native API approach
    mwexec("configctl abuseipdbchecker createalias");
    
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

