#!/usr/local/bin/php
<?php

/**
 * AbuseIPDB Checker ConfigD commands
 */

require_once("config.inc");
require_once("util.inc");
require_once("plugin_utils.inc");

// Get statistics about checked IPs and threats
function getStats() {
    $dbFile = '/var/db/abuseipdb_checker.db';
    $stats = [
        'total_checked' => 0,
        'total_threats' => 0,
        'checks_today' => 0,
        'last_run' => 'Never'
    ];
    
    if (!file_exists($dbFile)) {
        return json_encode($stats);
    }
    
    $db = new SQLite3($dbFile);
    
    // Get total IPs checked
    $result = $db->query('SELECT COUNT(*) FROM checked_ips');
    if ($result) {
        $row = $result->fetchArray();
        $stats['total_checked'] = $row[0];
    }
    
    // Get total threats
    $result = $db->query('SELECT COUNT(*) FROM checked_ips WHERE is_threat = 1');
    if ($result) {
        $row = $result->fetchArray();
        $stats['total_threats'] = $row[0];
    }
    
    // Get checks today
    $today = date('Y-m-d');
    $result = $db->query("SELECT checks_performed FROM daily_stats WHERE date = '$today'");
    if ($result) {
        $row = $result->fetchArray();
        if ($row) {
            $stats['checks_today'] = $row[0];
        }
    }
    
    // Get last run time
    $result = $db->query('SELECT last_checked FROM checked_ips ORDER BY last_checked DESC LIMIT 1');
    if ($result) {
        $row = $result->fetchArray();
        if ($row) {
            $stats['last_run'] = $row[0];
        }
    }
    
    $db->close();
    
    return json_encode($stats);
}

// Get log entries
function getLogs() {
    $logFile = '/var/log/abuseipdb_checker.log';
    
    if (!file_exists($logFile)) {
        return "Log file does not exist";
    }
    
    // Get the last 500 lines from the log file
    $output = [];
    exec("tail -n 500 $logFile 2>&1", $output);
    
    return implode("\n", $output);
}

// Get recent threats
function getThreats() {
    $dbFile = '/var/db/abuseipdb_checker.db';
    $threats = [];
    
    if (!file_exists($dbFile)) {
        return json_encode($threats);
    }
    
    $db = new SQLite3($dbFile);
    
    // Get recent threats with extra info from cached API responses
    $result = $db->query('
        SELECT ip, score, last_checked 
        FROM checked_ips 
        WHERE is_threat = 1 
        ORDER BY last_checked DESC 
        LIMIT 25
    ');
    
    if ($result) {
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $threats[] = [
                'ip' => $row['ip'],
                'score' => $row['score'],
                'last_checked' => $row['last_checked'],
                'country' => 'Unknown'
            ];
        }
    }
    
    $db->close();
    
    return json_encode($threats);
}

// Main execution
$action = isset($argv[1]) ? $argv[1] : '';

switch ($action) {
    case 'stats':
        echo getStats();
        break;
        
    case 'threats':
        echo getThreats();
        break;

    case 'logs':
        echo getLogs();
        break;
        
    default:
        echo "Unknown command: $action";
        break;
}