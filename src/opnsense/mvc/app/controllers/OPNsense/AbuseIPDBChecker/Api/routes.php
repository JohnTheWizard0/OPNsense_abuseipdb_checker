<?php

use OPNsense\Core\Api\ApiRouter;

$router = new ApiRouter();

// Service endpoints
$router->addRoute('/abuseipdbchecker/service/status', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'statusAction');
$router->addRoute('/abuseipdbchecker/service/start', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'startAction');
$router->addRoute('/abuseipdbchecker/service/stop', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'stopAction');
$router->addRoute('/abuseipdbchecker/service/restart', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'restartAction');
$router->addRoute('/abuseipdbchecker/service/validate', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'validateAction');
$router->addRoute('/abuseipdbchecker/service/stats', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'statsAction');
$router->addRoute('/abuseipdbchecker/service/threats', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'threatsAction');
$router->addRoute('/abuseipdbchecker/service/logs', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'logsAction');
$router->addRoute('/abuseipdbchecker/service/testip', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'testipAction');
$router->addRoute('/abuseipdbchecker/service/listips', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'listipsAction');
$router->addRoute('/abuseipdbchecker/service/allips', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'allipsAction');
$router->addRoute('/abuseipdbchecker/service/updatealias', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'updatealiasAction');
$router->addRoute('/abuseipdbchecker/service/exportthreats', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'exportthreatsAction');
$router->addRoute('/abuseipdbchecker/service/testalias', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'testaliasAction');

// IP Management endpoints
$router->addRoute('/abuseipdbchecker/service/removeip', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'removeipAction');
$router->addRoute('/abuseipdbchecker/service/marksafe', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'marksafeAction');
$router->addRoute('/abuseipdbchecker/service/unmarksafe', 'OPNsense\AbuseIPDBChecker\Api\ServiceController', 'unmarksafeAction');

// Settings endpoints
$router->addRoute('/abuseipdbchecker/settings/get', 'OPNsense\AbuseIPDBChecker\Api\SettingsController', 'getAction');
$router->addRoute('/abuseipdbchecker/settings/set', 'OPNsense\AbuseIPDBChecker\Api\SettingsController', 'setAction');

return $router;