<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\AbuseIPDBChecker\AbuseIPDBChecker;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = 'OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalModelName = 'abuseipdbchecker';

    /**
     * Execute plugin checks manually
     * @return array
     */
    public function runAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $response = $backend->configdRun('abuseipdbchecker run');
            return array("result" => $response);
        } else {
            return array("result" => "");
        }
    }

    /**
     * Get statistics about checked IPs and threats
     * @return array
     */
    public function statsAction()
    {
        $backend = new Backend();
        $response = json_decode($backend->configdRun('abuseipdbchecker stats'), true);
        return array("result" => "ok", "stats" => $response);
    }

    /**
     * Get recent threats from the database
     * @return array
     */
    public function threatsAction()
    {
        $backend = new Backend();
        $response = json_decode($backend->configdRun('abuseipdbchecker threats'), true);
        return array("result" => "ok", "threats" => $response);
    }

    /**
     * Get log entries from abuseipdb_checker.log
     * @return array
     */
    public function logsAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun('abuseipdbchecker logs');
        
        $logEntries = array();
        if (!empty($response)) {
            // Split log content into lines
            $lines = explode("\n", trim($response));
            
            // Process each line and extract info
            foreach ($lines as $line) {
                if (!empty(trim($line))) {
                    $logEntries[] = $line;
                }
            }
            
            // Only keep the last 500 entries to avoid overwhelming the UI
            if (count($logEntries) > 500) {
                $logEntries = array_slice($logEntries, -500);
            }
        }
        
        return array("result" => "ok", "logs" => $logEntries);
    }
}