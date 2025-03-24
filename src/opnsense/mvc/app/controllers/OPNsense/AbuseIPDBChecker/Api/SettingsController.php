<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

/**
 * Class SettingsController Handles settings related API actions for the AbuseIPDBChecker
 * @package OPNsense\AbuseIPDBChecker
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = 'OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalModelName = 'abuseipdbchecker';
}