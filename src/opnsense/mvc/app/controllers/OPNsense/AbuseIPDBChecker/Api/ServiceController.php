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
        if (!$this->request->isPost()) {
            return ["status" => "failed", "message" => "Method not allowed"];
        }
        
        // Get the raw POST data first
        $rawData = $this->request->getRawBody();
        $postData = json_decode($rawData, true);
        
        // Try multiple ways to get the IP
        $ip = '';
        if (isset($postData['ip'])) {
            $ip = $postData['ip'];
        } elseif ($this->request->hasPost('ip')) {
            $ip = $this->request->getPost('ip', 'string', '');
        }
        
        if (empty($ip)) {
            return ["status" => "failed", "message" => "IP address is required"];
        }
        
        // Basic IP validation
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ["status" => "failed", "message" => "Invalid IP address format"];
        }
        
        // Ensure directories exist
        $this->ensureDirectories();
        
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker testip {$ip}");
        $bckresult = json_decode(trim($response), true);
        
        if ($bckresult !== null) {
            return $bckresult;
        }
        
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