<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableModelControllerBases;
use OPNsense\Core\Config;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = 'OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalModelName = 'abuseipdbchecker';
}