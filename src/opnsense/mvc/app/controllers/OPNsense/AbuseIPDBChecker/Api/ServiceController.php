<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\AbuseIPDBChecker\AbuseIPDBChecker;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalServiceTemplate = 'OPNsense/AbuseIPDBChecker';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'abuseipdbchecker';
    
    /**
     * Determine if we need to force restart on reconfigure
     */
    protected function reconfigureForceRestart()
    {
        return 0;
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