<?php

namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalServiceTemplate = 'OPNsense/AbuseIPDBChecker';
    protected static $internalServiceEnabled = 'general.Enabled';
    protected static $internalServiceName = 'abuseipdbchecker';


    /**
     * Ensure backend actions exist
     */
    public function reloadAction()
    {
        if ($this->request->isPost()) {
            // First apply template
            $backend = new Backend();
            $bckresult = trim($backend->configdRun('template reload OPNsense/AbuseIPDBChecker'));
            return array("status" => $bckresult);
        }
        return array("status" => "failed");
    }

    /**
     * Initialize database if needed
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
     * Get logs
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
     * Run a manual check
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
     * Get statistics
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
     * Get recent threats
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
     * Test a specific IP
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
        
        // Ensure directories exist
        $this->ensureDirectories();
        
        // Log the command for debugging
        $command = "abuseipdbchecker testip {$ip}";
        syslog(LOG_NOTICE, "AbuseIPDBChecker: Executing command: {$command}");
        
        $backend = new Backend();
        $response = $backend->configdRun($command);
        
        // Debug: Log the raw response
        syslog(LOG_NOTICE, "AbuseIPDBChecker: Raw response: " . substr($response, 0, 200));
        
        // Clean the response more carefully
        $response = trim($response);
        
        // Try to decode JSON
        $bckresult = json_decode($response, true);
        if ($bckresult !== null) {
            syslog(LOG_NOTICE, "AbuseIPDBChecker: Successfully parsed JSON response");
            return $bckresult;
        }
        
        // If JSON decode failed, try to execute directly
        syslog(LOG_ERR, "AbuseIPDBChecker: JSON decode failed, trying direct execution");
        $scriptPath = "/usr/local/opnsense/scripts/OPNsense/AbuseIPDBChecker/checker.py";
        $output = [];
        $returnCode = 0;
        
        exec("python3 {$scriptPath} testip {$ip} 2>&1", $output, $returnCode);
        
        if ($returnCode === 0 && !empty($output)) {
            // Get the last line as it's likely the JSON output
            $jsonOutput = end($output);
            $bckresult = json_decode($jsonOutput, true);
            if ($bckresult !== null) {
                syslog(LOG_NOTICE, "AbuseIPDBChecker: Direct execution successful");
                return $bckresult;
            }
        }
        
        // If all else fails, create a default response that indicates an error
        return [
            "status" => "error",
            "message" => "Could not parse response from backend. Check logs for details.",
            "ip" => $ip,
            "is_threat" => false,
            "abuse_score" => 0
        ];
    }

    /**
     * Helper function to ensure required directories exist
     */
    private function ensureDirectories()
    {
        $dirs = [
            '/var/log/abuseipdbchecker' => 0755,
            '/var/db/abuseipdbchecker' => 0755,
            '/usr/local/etc/abuseipdbchecker' => 0755
        ];
        
        foreach ($dirs as $dir => $mode) {
            if (!file_exists($dir)) {
                mkdir($dir, $mode, true);
                chmod($dir, $mode);
            }
        }
    }

    protected function reconfigureForceRestart()
    {
        return 0;
    }
}