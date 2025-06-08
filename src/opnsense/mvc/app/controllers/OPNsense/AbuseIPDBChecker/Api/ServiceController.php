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
     * validate configuration before service start
     */
    public function validateAction()
    {
        $result = array("status" => "failed");
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker validate");
            $bckresult = json_decode(trim($response), true);
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["status" => "failed", "message" => "Unable to validate configuration"];
    }

    /**
     * start abuseipdbchecker service WITH PRE-VALIDATION
     */
    public function startAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $backend = new Backend();
            
            // STEP 1: Validate configuration before starting
            $validation_response = $backend->configdRun("abuseipdbchecker validate");
            $validation_result = json_decode(trim($validation_response), true);
            
            if ($validation_result && $validation_result['status'] === 'error') {
                return array(
                    "result" => "failed",
                    "status" => "validation_error",
                    "message" => "Configuration validation failed: " . $validation_result['message']
                );
            }
            
            if ($validation_result && isset($validation_result['errors']) && !empty($validation_result['errors'])) {
                return array(
                    "result" => "failed", 
                    "status" => "validation_error",
                    "message" => "Configuration errors must be fixed before starting: " . implode(', ', $validation_result['errors'])
                );
            }
            
            // STEP 2: Start service only if validation passes
            $response = $backend->configdRun("abuseipdbchecker start");
            if (strpos($response, "OK") !== false || strpos($response, "Starting") !== false || strpos($response, "started") !== false) {
                $result['result'] = "OK";
                $result['status'] = "ok";
                $result['message'] = "Service started successfully";
            } else {
                $result['message'] = trim($response);
            }
        }
        return $result;
    }

    /**
     * stop abuseipdbchecker service
     */
    public function stopAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker stop");
            if (strpos($response, "OK") !== false || strpos($response, "Stopping") !== false || strpos($response, "stopped") !== false) {
                $result['result'] = "OK";
                $result['status'] = "ok";
            } else {
                $result['message'] = trim($response);
            }
        }
        return $result;
    }

    /**
     * restart abuseipdbchecker service
     */
    public function restartAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker restart");
            if (strpos($response, "OK") !== false || strpos($response, "Starting") !== false || strpos($response, "Restart") !== false) {
                $result['result'] = "OK";
                $result['status'] = "ok";
            } else {
                $result['message'] = trim($response);
            }
        }
        return $result;
    }

    /**
     * retrieve status of abuseipdbchecker
     */
    public function statusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker status");
        
        $result = array();
        if (strpos($response, "is running") !== false || strpos($response, "EXIT_CODE:0") !== false) {
            $result['status'] = 'running';
        } else {
            $result['status'] = 'stopped';
        }
        
        return $result;
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
     * get recent threats with pagination and search
     */
    public function threatsAction()
    {
        $page = (int)$this->request->get('page', 'int', 1);
        $limit = (int)$this->request->get('limit', 'int', 20);
        $search = $this->request->get('search', 'string', '');
        $include_marked_safe = $this->request->get('include_marked_safe', 'string', 'true') === 'true';
        
        $offset = ($page - 1) * $limit;
        
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker threats " . 
            escapeshellarg($limit) . " " . 
            escapeshellarg($offset) . " " . 
            escapeshellarg($search) . " " .
            escapeshellarg($include_marked_safe ? '1' : '0'));
            
        $bckresult = json_decode(trim($response), true);
        if ($bckresult !== null) {
            // Add pagination info
            if (isset($bckresult['total_count'])) {
                $bckresult['pagination'] = [
                    'page' => $page,
                    'limit' => $limit,
                    'total_pages' => ceil($bckresult['total_count'] / $limit),
                    'has_next' => ($offset + $limit) < $bckresult['total_count'],
                    'has_prev' => $page > 1
                ];
            }
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
     * remove IP from threats
     */
    public function removeipAction()
    {
        if ($this->request->isPost()) {
            $input = json_decode($this->request->getRawBody(), true);
            $ip = isset($input['ip']) ? $input['ip'] : $this->request->getPost('ip', 'string', '');
            
            if (empty($ip)) {
                return array("status" => "failed", "message" => "IP address is required");
            }
            
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return array("status" => "failed", "message" => "Invalid IP address format");
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker removeip " . escapeshellarg($ip));
            $bckresult = json_decode(trim($response), true);
            
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["status" => "failed", "message" => "Unable to remove IP"];
    }

    /**
     * mark IP as safe
     */
    public function marksafeAction()
    {
        if ($this->request->isPost()) {
            $input = json_decode($this->request->getRawBody(), true);
            $ip = isset($input['ip']) ? $input['ip'] : $this->request->getPost('ip', 'string', '');
            $marked_by = isset($input['marked_by']) ? $input['marked_by'] : 'admin';
            
            if (empty($ip)) {
                return array("status" => "failed", "message" => "IP address is required");
            }
            
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return array("status" => "failed", "message" => "Invalid IP address format");
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker marksafe " . 
                escapeshellarg($ip) . " " . escapeshellarg($marked_by));
            $bckresult = json_decode(trim($response), true);
            
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["status" => "failed", "message" => "Unable to mark IP as safe"];
    }

    /**
     * unmark IP as safe
     */
    public function unmarksafeAction()
    {
        if ($this->request->isPost()) {
            $input = json_decode($this->request->getRawBody(), true);
            $ip = isset($input['ip']) ? $input['ip'] : $this->request->getPost('ip', 'string', '');
            
            if (empty($ip)) {
                return array("status" => "failed", "message" => "IP address is required");
            }
            
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return array("status" => "failed", "message" => "Invalid IP address format");
            }
            
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker unmarksafe " . escapeshellarg($ip));
            $bckresult = json_decode(trim($response), true);
            
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["status" => "failed", "message" => "Unable to unmark IP as safe"];
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

    public function batchstatusAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker batchstatus");
        $bckresult = json_decode(trim($response), true);
        if ($bckresult !== null) {
            return $bckresult;
        }
        return ["status" => "failed", "message" => "Unable to retrieve batch status"];
    }

    /**
     * get all checked IPs with pagination and search
     */
    public function allipsAction()
    {
        $page = (int)$this->request->get('page', 'int', 1);
        $limit = (int)$this->request->get('limit', 'int', 20);
        $search = $this->request->get('search', 'string', '');
        
        $offset = ($page - 1) * $limit;
        
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker allips " . 
            escapeshellarg($limit) . " " . 
            escapeshellarg($offset) . " " . 
            escapeshellarg($search));
            
        $bckresult = json_decode(trim($response), true);
        if ($bckresult !== null) {
            // Add pagination info
            if (isset($bckresult['total_count'])) {
                $bckresult['pagination'] = [
                    'page' => $page,
                    'limit' => $limit,
                    'total_pages' => ceil($bckresult['total_count'] / $limit),
                    'has_next' => ($offset + $limit) < $bckresult['total_count'],
                    'has_prev' => $page > 1
                ];
            }
            return $bckresult;
        }
        return ["status" => "failed", "message" => "Unable to retrieve all checked IPs"];
    }

    public function updatealiasAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker updatealias");
            $bckresult = json_decode(trim($response), true);
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["status" => "failed", "message" => "Unable to update alias"];
    }

    public function exportthreatsAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("abuseipdbchecker exportthreats");
        $bckresult = json_decode(trim($response), true);
        if ($bckresult !== null) {
            return $bckresult;
        }
        return ["status" => "failed", "message" => "Unable to export threats"];
    }

    public function testaliasAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun("abuseipdbchecker testalias");
            $bckresult = json_decode(trim($response), true);
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["status" => "failed", "message" => "Unable to test alias"];
    }

    protected function reconfigureForceRestart()
    {
        return 0;
    }
}