<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = 'OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalModelName = 'abuseipdbchecker';
    
    // Try adding explicit methods to debug
    public function getAction() 
    {
        $result = array("result" => "failed");
        if ($this->request->isGet()) {
            $mdl = $this->getModel();
            if ($mdl) {
                $result = array("abuseipdbchecker" => $mdl->getNodes());
            }
        }
        return $result;
    }
    
    public function setAction() 
    {
        if ($this->request->isPost() && $this->request->hasPost("abuseipdbchecker")) {
            $result = $this->setModelProperties(
                "abuseipdbchecker", 
                $this->request->getPost("abuseipdbchecker")
            );
            
            // Force save the model to be certain
            $mdl = $this->getModel();
            if ($mdl) {
                $mdl->serializeToConfig();
                Config::getInstance()->save();
            }
            
            return $result;
        }
        return array("result" => "failed");
    }
}