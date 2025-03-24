<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\AbuseIPDBChecker\AbuseIPDBChecker;
use OPNsense\Core\Backend;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalModelName = 'abuseipdbchecker';
    
    public function getAction()
    {
        $result = array();
        $mdlAbuseIPDB = new AbuseIPDBChecker();
        $result['abuseipdbchecker'] = $mdlAbuseIPDB->getNodes();
        return $result;
    }
    
    public function setAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            // Get post data and update model
            $mdlAbuseIPDB = new AbuseIPDBChecker();
            $mdlAbuseIPDB->setNodes($this->request->getPost("abuseipdbchecker"));
            
            // Validate model
            $validations = $mdlAbuseIPDB->performValidation();
            
            if (count($validations) > 0) {
                // Input validation errors found
                $result["validations"] = array();
                foreach ($validations as $field => $message) {
                    $fieldname = str_replace($mdlAbuseIPDB->__toString() . ".", "", $message->getField());
                    $result["validations"][$fieldname] = $message->getMessage();
                }
            } else {
                // Save model to config
                $mdlAbuseIPDB->serializeToConfig();
                Config::getInstance()->save();
                
                // Apply configuration changes
                $backend = new Backend();
                $backend->configdRun('template reload OPNsense/AbuseIPDBChecker');
                
                $result = array("result" => "saved");
            }
        }
        return $result;
    }
}