<?php

namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    /**
     * Get service status
     * @return array
     */
    public function statusAction()
    {
        $this->sessionClose();
        
        $backend = new Backend();
        $response = trim($backend->configdRun("abuseipdbchecker status"));
        
        // OPNsense expects this exact format for service display
        if (strpos($response, 'is running') !== false) {
            return array(
                "status" => "running",
                "running" => 1
            );
        } else {
            return array(
                "status" => "stopped", 
                "running" => 0
            );
        }
    }

    /**
     * Start service
     * @return array
     */
    public function startAction()
    {
        $this->sessionClose();
        
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('template reload OPNsense/AbuseIPDBChecker');
            $backend->configdRun("abuseipdbchecker start");
            
            sleep(2);
            return $this->statusAction();
        }
        return ["status" => "failed"];
    }

    /**
     * Stop service
     * @return array
     */
    public function stopAction()
    {
        $this->sessionClose();
        
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun("abuseipdbchecker stop");
            
            sleep(1);
            return $this->statusAction();
        }
        return ["status" => "failed"];
    }

    /**
     * Restart service
     * @return array
     */
    public function restartAction()
    {
        $this->sessionClose();
        
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('template reload OPNsense/AbuseIPDBChecker');
            $backend->configdRun("abuseipdbchecker restart");
            
            sleep(2);
            return $this->statusAction();
        }
        return ["status" => "failed"];
    }

    // Keep all other methods unchanged...
    public function statsAction()
    {
        $this->sessionClose();
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker stats");
        $result = json_decode(trim($response), true);
        return $result ?: ["status" => "failed", "message" => "Unable to retrieve statistics"];
    }

    public function threatsAction()
    {
        $this->sessionClose();
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker threats");
        $result = json_decode(trim($response), true);
        return $result ?: ["status" => "failed", "message" => "Unable to retrieve threats"];
    }

    public function logsAction()
    {
        $this->sessionClose();
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker logs");
        $result = json_decode(trim($response), true);
        return $result ?: ["status" => "failed", "message" => "Unable to retrieve logs"];
    }

    public function testipAction()
    {
        $this->sessionClose();
        
        $ip = $this->request->getPost('ip', 'string', '');
        if (empty($ip)) {
            return ["status" => "failed", "message" => "IP address is required"];
        }
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ["status" => "failed", "message" => "Invalid IP address format"];
        }
        
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker testip {$ip}");
        $result = json_decode(trim($response), true);
        
        return $result ?: [
            "status" => "error",
            "message" => "Could not parse response",
            "ip" => $ip,
            "is_threat" => false,
            "abuse_score" => 0
        ];
    }
}