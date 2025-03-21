<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\AbuseIPDBChecker\AbuseIPDBChecker;

class ServiceController extends ApiControllerBase
{
    /**
     * Reconfigure AbuseIPDB Checker
     * @return array
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            // Generate config file using the template system
            $backend = new Backend();
            $response = $backend->configdRun('template reload OPNsense/AbuseIPDBChecker');
            
            // Restart service if model is enabled
            $model = new AbuseIPDBChecker();
            if ((string)$model->general->enabled == '1') {
                $response = $backend->configdRun('service restart abuseipdbchecker');
            } else {
                $response = $backend->configdRun('service stop abuseipdbchecker');
            }
            
            return ['status' => 'ok', 'message' => $response];
        }
        
        return ['status' => 'failed', 'message' => 'Only POST requests allowed'];
    }
    
    /**
     * Get service status
     * @return array
     */
    public function statusAction()
    {
        $backend = new Backend();
        $model = new AbuseIPDBChecker();
        $response = [];
        
        if ((string)$model->general->enabled == '1') {
            $response['status'] = trim($backend->configdRun('service status abuseipdbchecker'));
            $response['enabled'] = true;
        } else {
            $response['status'] = 'disabled';
            $response['enabled'] = false;
        }
        
        return $response;
    }

    /**
     * Run AbuseIPDB Checker manually
     * @return array
     */
    public function runAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun('abuseipdbchecker run');
            return ['status' => 'ok', 'result' => $response];
        }
        
        return ['status' => 'failed', 'message' => 'Only POST requests allowed'];
    }
}