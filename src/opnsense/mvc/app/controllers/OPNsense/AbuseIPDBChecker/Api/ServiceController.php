<?php

/**
 *    Copyright (C) 2023 Your Name
 *
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 *
 */

namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Class ServiceController
 * @package OPNsense\AbuseIPDBChecker\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalServiceTemplate = 'OPNsense/AbuseIPDBChecker';
    protected static $internalServiceEnabled = 'general.Enabled';
    protected static $internalServiceName = 'abuseipdbchecker';
    
    /**
     * reconfigure AbuseIPDBChecker
     */
    public function reloadAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            $backend = new Backend();
            
            // Check if model data exists in config
            $configObj = Config::getInstance()->object();
            $modelExists = isset($configObj->OPNsense) && isset($configObj->OPNsense->abuseipdbchecker);
            
            if (!$modelExists) {
                // Configuration doesn't exist yet, force create it
                $model = new \OPNsense\AbuseIPDBChecker\AbuseIPDBChecker();
                $model->general->Enabled = 1; // Force enable
                $model->serializeToConfig();
                
                // Save config
                Config::getInstance()->save();
            }
            
            // Now reload template
            $status = strtolower(trim($backend->configdRun('template reload OPNsense/AbuseIPDBChecker')));
            
            if ($status == "ok") {
                // Ensure directory exists
                if (!file_exists('/usr/local/etc/abuseipdbchecker')) {
                    mkdir('/usr/local/etc/abuseipdbchecker', 0755, true);
                }
                
                // Initialize database if it doesn't exist
                if (!file_exists('/var/db/abuseipdbchecker/abuseipdb.db')) {
                    $backend->configdRun('abuseipdbchecker initdb');
                }
            }
        }
        return ["status" => $status];
    }

    /**
     * get service status
     * @return array
     */
    public function statusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker status");
        $status = json_decode($response, true);
        
        if ($status !== null) {
            return $status;
        } else {
            return array("status" => "unknown");
        }
    }

    /**
     * get logs
     */
    public function logsAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker logs");
        $bckresult = json_decode(trim($response), true);
        if ($bckresult !== null) {
            return $bckresult;
        }
        return ["status" => "failed", "message" => "Unable to retrieve logs"];
    }

    /**
     * run a manual check
     */
    public function runAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker run");
            $bckresult = json_decode(trim($response), true);
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["status" => "failed", "message" => "Unable to run manual check"];
    }

    /**
     * initialize database
     */
    public function initdbAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker initdb");
            $bckresult = json_decode(trim($response), true);
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["status" => "failed", "message" => "Unable to initialize database"];
    }

    /**
     * get statistics
     */
    public function statsAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker stats");
        $bckresult = json_decode(trim($response), true);
        if ($bckresult !== null) {
            return $bckresult;
        }
        return ["status" => "failed", "message" => "Unable to retrieve statistics"];
    }

    /**
     * get recent threats
     */
    public function threatsAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker threats");
        $bckresult = json_decode(trim($response), true);
        if ($bckresult !== null) {
            return $bckresult;
        }
        return ["status" => "failed", "message" => "Unable to retrieve recent threats"];
    }
    
    /**
     * test a specific IP
     */
    public function testipAction()
    {
        $ip = $this->request->getPost('ip', 'string', '');
        if (empty($ip)) {
            return ["status" => "failed", "message" => "IP address is required"];
        }
        
        // Basic IP validation
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ["status" => "failed", "message" => "Invalid IP address format"];
        }
        
        // Create log directory first to ensure permissions
        $logDir = '/var/log/abuseipdbchecker';
        if (!file_exists($logDir)) {
            @mkdir($logDir, 0755, true);
            @chmod($logDir, 0755);
            @chown($logDir, 'www');
            @chgrp($logDir, 'www');
        }
        
        // Initialize database if needed
        $dbDir = '/var/db/abuseipdbchecker';
        if (!file_exists($dbDir)) {
            @mkdir($dbDir, 0755, true);
            @chmod($dbDir, 0755);
            @chown($dbDir, 'www');
            @chgrp($dbDir, 'www');
        }
        
        // Log the command that will be executed for debugging
        $command = "abuseipdbchecker testip {$ip}";
        syslog(LOG_NOTICE, "AbuseIPDBChecker: Executing command: {$command}");
        
        $backend = new Backend();
        $response = $backend->configdRun($command);
        
        // Check for empty response
        if (empty($response)) {
            // Try direct execution as fallback and log the result
            $scriptPath = "/usr/local/opnsense/scripts/OPNsense/AbuseIPDBChecker/checker.py";
            $output = [];
            $returnCode = 0;
            
            // Log the fallback command
            syslog(LOG_NOTICE, "AbuseIPDBChecker: Direct execution fallback: {$scriptPath} testip {$ip}");
            
            exec("python3 {$scriptPath} testip {$ip} 2>&1", $output, $returnCode);
            syslog(LOG_NOTICE, "AbuseIPDBChecker: Direct execution returned code {$returnCode}");
            
            if ($returnCode === 0 && !empty($output)) {
                $response = implode("\n", $output);
                syslog(LOG_NOTICE, "AbuseIPDBChecker: Direct execution successful");
            } else {
                syslog(LOG_ERR, "AbuseIPDBChecker: Direct execution failed: " . implode("\n", $output));
                return ["status" => "failed", "message" => "No response from backend. Script execution failed with code {$returnCode}. Check script permissions and logs."];
            }
        }
        
        $bckresult = json_decode(trim($response), true);
        if ($bckresult !== null) {
            // Log the successful JSON parsing
            syslog(LOG_NOTICE, "AbuseIPDBChecker: Successfully parsed JSON response");
            return $bckresult;
        }
        
        // If we can't parse the JSON, log the actual response for debugging
        syslog(LOG_ERR, "AbuseIPDBChecker: Invalid JSON response: " . substr($response, 0, 200));
        
        // Try to sanitize the response if possible
        $cleanResponse = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $response);
        $sanitizedResult = json_decode(trim($cleanResponse), true);
        
        if ($sanitizedResult !== null) {
            syslog(LOG_NOTICE, "AbuseIPDBChecker: Recovered JSON after sanitizing");
            return $sanitizedResult;
        }
        
        return ["status" => "failed", "message" => "Unable to parse backend response. See system logs."];
    }

    protected function reconfigureForceRestart()
    {
        return 0;
    }
}