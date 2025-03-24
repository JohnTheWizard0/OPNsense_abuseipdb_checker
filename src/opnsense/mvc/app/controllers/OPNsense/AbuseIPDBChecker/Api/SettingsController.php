<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\AbuseIPDBChecker\AbuseIPDBChecker;

class SettingsController extends ApiControllerBase
{
    public function getAction() 
    {
        $model = new AbuseIPDBChecker();
        return array("abuseipdbchecker" => $model->getNodes());
    }
    
    public function setAction() 
    {
        if ($this->request->isPost() && $this->request->hasPost("abuseipdbchecker")) {
            $model = new AbuseIPDBChecker();
            $model->setNodes($this->request->getPost("abuseipdbchecker"));
            
            $validations = $model->performValidation();
            if (count($validations) > 0) {
                $response = array("result" => "failed", "validations" => array());
                foreach ($validations as $field => $message) {
                    $response["validations"]["abuseipdbchecker." . $message->getField()] = $message->getMessage();
                }
                return $response;
            }
            
            // Save model to config and persist
            $model->serializeToConfig();
            Config::getInstance()->save();
            
            // Apply changes using the template
            \OPNsense\Core\Backend::configdRun('template reload OPNsense/AbuseIPDBChecker');
            
            return array("result" => "saved");
        }
        return array("result" => "failed");
    }
}