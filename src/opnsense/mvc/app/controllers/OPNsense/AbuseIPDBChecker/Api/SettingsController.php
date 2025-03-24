<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;

class SettingsController extends ApiControllerBase
{
    public function getAction()
    {
        return $this->getBase('abuseipdbchecker');
    }
    
    public function setAction()
    {
        return $this->setBase('abuseipdbchecker');
    }

    public function searchAction()
    {
        return $this->searchBase('abuseipdbchecker');
    }
}