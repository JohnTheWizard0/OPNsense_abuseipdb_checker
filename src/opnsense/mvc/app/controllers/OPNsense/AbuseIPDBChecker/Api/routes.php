<?php

use OPNsense\Core\Api\ApiRouter;

$router = new ApiRouter();

// Service endpoints
$router->addRoute('/abuseipdbchecker/service/status', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'statusAction');
$router->addRoute('/abuseipdbchecker/service/start', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'startAction');
$router->addRoute('/abuseipdbchecker/service/stop', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'stopAction');
$router->addRoute('/abuseipdbchecker/service/restart', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'restartAction');
$router->addRoute('/abuseipdbchecker/service/stats', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'statsAction');
$router->addRoute('/abuseipdbchecker/service/threats', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'threatsAction');
$router->addRoute('/abuseipdbchecker/service/logs', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'logsAction');
$router->addRoute('/abuseipdbchecker/service/testip', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'testipAction');
$router->addRoute('/abuseipdbchecker/service/listips', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'listipsAction');

// Settings endpoints
$router->addRoute('/abuseipdbchecker/settings/get', 'OPNsense\AbuseIPDBChecker\Api\SettingsController', 'getAction');
$router->addRoute('/abuseipdbchecker/settings/set', 'OPNsense\AbuseIPDBChecker\Api\SettingsController', 'setAction');

return $router;