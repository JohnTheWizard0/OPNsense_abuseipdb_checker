<?php

/*
 * AbuseIPDBChecker - OPNsense plugin for checking IPs against AbuseIPDB
 * Copyright (c) 2025 OPNsense Team
 * All rights reserved.
 */

/**
 * Register service
 * @return array
 */
function abuseipdbchecker_services()
{
    global $config;
    
    $services = array();
    
    if (isset($config['OPNsense']['abuseipdbchecker']['general']['enabled']) &&
        $config['OPNsense']['abuseipdbchecker']['general']['enabled'] == 1) {
        $services[] = array(
            'description' => gettext('AbuseIPDB Checker'),
            'configd' => array(
                'restart' => array('abuseipdbchecker restart'),
                'start' => array('abuseipdbchecker start'),
                'stop' => array('abuseipdbchecker stop'),
            ),
            'name' => 'abuseipdbchecker',
            'pidfile' => '/var/run/abuseipdbchecker.pid'
        );
    }
    
    return $services;
}

/**
 * Register a XMLRPC sync hook 
 * @return array
 */
function abuseipdbchecker_xmlrpc_sync()
{
    $result = array();
    
    $result[] = array(
        'description' => gettext('AbuseIPDB Checker'),
        'section' => 'OPNsense.abuseipdbchecker',
        'id' => 'abuseipdbchecker'
    );
    
    return $result;
}

/**
 * Create cron jobs
 * @return array
 */
function abuseipdbchecker_cron()
{
    global $config;
    
    $jobs = array();
    
    if (isset($config['OPNsense']['abuseipdbchecker']['general']['enabled']) &&
        $config['OPNsense']['abuseipdbchecker']['general']['enabled'] == 1) {
        $jobs[] = array(
            'description' => gettext('AbuseIPDB Checker'),
            'command' => '/usr/local/opnsense/scripts/AbuseIPDBChecker/checker.py',
            'parameters' => '--config /usr/local/etc/abuseipdb_checker.conf',
            'msg' => gettext('Running AbuseIPDB Checker'),
            'hourly' => true
        );
    }
    
    return $jobs;
}