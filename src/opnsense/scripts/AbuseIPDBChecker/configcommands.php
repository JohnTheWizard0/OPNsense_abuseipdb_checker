#!/usr/local/bin/php
<?php

/**
 * AbuseIPDB Checker ConfigD commands
 */

use OPNsense\Core\Config;
use OPNsense\AbuseIPDBChecker\AbuseIPDBChecker;

require_once("config.inc");
require_once("util.inc");
require_once("plugin_utils.inc");

// Convert model settings to configuration file
function generateConfigFile() {
    $model = new AbuseIPDBChecker();
    $configPath = '/usr/local/etc/abuseipdb_checker.conf';
    
    $config = new \ConfigParser\ConfigParser();
    
    // General section
    $config->addSection('General');
    $config->set('General', 'LogFile', $model->general->logFile);
    $config->set('General', 'CheckFrequency', $model->general->checkFrequency);
    $config->set('General', 'AbuseScoreThreshold', $model->general->abuseScoreThreshold);
    $config->set('General', 'DailyCheckLimit', $model->general->dailyCheckLimit);
    $config->set('General', 'IgnoreBlockedConnections', $model->general->ignoreBlockedConnections ? 'true' : 'false');
    
    // Network settings
    $config->addSection('NetworkSettings');
    $config->set('NetworkSettings', 'LANSubnets', $model->network->lanSubnets);
    $config->set('NetworkSettings', 'IgnoreProtocols', $model->network->ignoreProtocols);
    
    // API settings
    $config->addSection('AbuseIPDB');
    $config->set('AbuseIPDB', 'APIKey', $model->api->key);
    $config->set('AbuseIPDB', 'APIEndpoint', $model->api->endpoint);
    $config->set('AbuseIPDB', 'MaxAge', $model->api->maxAge);
    
    // Email settings
    $config->addSection('Email');
    $config->set('Email', 'Enabled', $model->email->enabled ? 'true' : 'false');
    $config->set('Email', 'SMTPServer', $model->email->smtpServer);
    $config->set('Email', 'SMTPPort', $model->email->smtpPort);
    $config->set('Email', 'SMTPUsername', $model->email->smtpUsername);
    $config->set('Email', 'SMTPPassword', $model->email->smtpPassword);
    $config->set('Email', 'FromAddress', $model->email->fromAddress);
    $config->set('Email', 'ToAddress', $model->email->toAddress);
    $config->set('Email', 'UseTLS', $model->email->useTLS ? 'true' : 'false');
    
    // Write to file
    file_put_contents($configPath, $config->dump());
    chmod($configPath, 0600); // Secure permissions as it contains API key and passwords
    
    return true;
}

// Execute the checker script
function runChecker() {
    $output = [];
    $returnCode = 0;
    
    // Run the script
    exec('/usr/local/opnsense/scripts/AbuseIPDBChecker/checker.py 2>&1', $output, $returnCode);
    
    return implode("\n", $output);
}

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
                // Additional details would need to be stored in a separate table
                // to preserve API response data for each IP
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
    case 'generate-config':
        echo generateConfigFile() ? "OK" : "FAILED";
        break;
        
    case 'run':
        echo runChecker();
        break;
        
    case 'stats':
        echo getStats();
        break;
        
    case 'threats':
        echo getThreats();
        break;
        
    default:
        echo "Unknown command: $action";
        break;
}
