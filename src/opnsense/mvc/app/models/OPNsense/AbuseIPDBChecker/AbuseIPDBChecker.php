<?php
namespace OPNsense\AbuseIPDBChecker;

use OPNsense\Base\BaseModel;

class AbuseIPDBChecker extends BaseModel
{
    /**
     * get the config path for this model
     * @return string
     */
    public function getConfigPath()
    {
        return array('abuseipdbchecker');
    }
}