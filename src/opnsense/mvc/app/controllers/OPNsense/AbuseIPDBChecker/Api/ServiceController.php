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
            // Generate config file
            $backend = new Backend();
            $response = $backend->configdRun('abuseipdbchecker generate-config');
            
            // Restart service if model is enabled
            $model = new AbuseIPDBChecker();
            if ((string)$model->general->enabled == '1') {
                $response = $backend->configdRun('abuseipdbchecker restart');
            } else {
                $response = $backend->configdRun('abuseipdbchecker stop');
            }
            
            return array('status' => 'ok', 'message' => $response);
        }
        
        return array('status' => 'failed', 'message' => 'Only POST requests allowed');
    }
    
    /**
     * Get service status
     * @return array
     */
    public function statusAction()
    {
        $backend = new Backend();
        $model = new AbuseIPDBChecker();
        $response = array();
        
        if ((string)$model->general->enabled == '1') {
            $response['status'] = trim($backend->configdRun('abuseipdbchecker status'));
            $response['enabled'] = true;
        } else {
            $response['status'] = 'disabled';
            $response['enabled'] = false;
        }
        
        return $response;
    }
}