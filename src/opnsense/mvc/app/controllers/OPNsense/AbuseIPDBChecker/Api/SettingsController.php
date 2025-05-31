<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\Backend;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalModelName = 'abuseipdbchecker';
    
    public function getAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $mdl = $this->getModel();
            $result['abuseipdbchecker'] = $mdl->getNodes();
        }
        return $result;
    }
    
    public function setAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $mdl = $this->getModel();
            $mdl->setNodes($this->request->getPost("abuseipdbchecker"));
            
            $valMsgs = $mdl->performValidation();
            foreach ($valMsgs as $field => $msg) {
                if (!isset($result["validations"])) {
                    $result["validations"] = array();
                }
                $result["validations"]["abuseipdbchecker.".$msg->getField()] = $msg->getMessage();
            }
            
            if (!isset($result["validations"])) {
                $mdl->serializeToConfig();
                Config::getInstance()->save();
                
                // Regenerate the config file from template
                $backend = new Backend();
                $bckresult = trim($backend->configdRun('template reload OPNsense/AbuseIPDBChecker'));
                
                $result = array("result" => "saved");
            }
        }
        return $result;
    }
}