<?php

namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalServiceTemplate = 'OPNsense/AbuseIPDBChecker';
    protected static $internalServiceEnabled = 'general.Enabled';
    protected static $internalServiceName = 'abuseipdbchecker';

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
        $result = array();
        
        if ($this->request->isPost()) {
            // Get IP from JSON body or POST data
            $ip = '';
            $input = json_decode($this->request->getRawBody(), true);
            
            if (isset($input['ip'])) {
                $ip = $input['ip'];
            } else {
                $ip = $this->request->getPost('ip', 'string', '');
            }
            
            if (empty($ip)) {
                return array("status" => "failed", "message" => "IP address is required");
            }
            
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return array("status" => "failed", "message" => "Invalid IP address format");
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker testip " . escapeshellarg($ip));
            $bckresult = json_decode(trim($response), true);
            
            if ($bckresult !== null) {
                return $bckresult;
            }
            
            return array(
                "status" => "error",
                "message" => "Backend execution failed",
                "ip" => $ip,
                "is_threat" => false,
                "abuse_score" => 0
            );
        }
        
        return array("status" => "failed", "message" => "POST request required");
    }

    /**
     * list external IPs from firewall logs
     */
    public function listipsAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker listips");
        $bckresult = json_decode(trim($response), true);
        if ($bckresult !== null) {
            return $bckresult;
        }
        return ["status" => "failed", "message" => "Unable to retrieve external IPs"];
    }

    protected function reconfigureForceRestart()
    {
        return 0;
    }
}