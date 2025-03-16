<?php
namespace OPNsense\AbuseIPDBChecker\Model;

use OPNsense\Base\BaseModel;

class AbuseIPDBChecker extends BaseModel
{
    public function getConfigPath()
    {
        return '/usr/local/etc/abuseipdb_checker.conf';
    }
}
