<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\AbuseIPDBChecker\AbuseIPDBChecker;

class SettingsController extends ApiControllerBase
{
    /**
     * Retrieve plugin settings
     * @return array
     */
    public function getAction()
    {
        $model = new AbuseIPDBChecker();
        return [
            'abuseipdbchecker' => $model->getNodes()
        ];
    }

    /**
     * Update plugin settings
     * @return array
     */
    public function setAction()
    {
        $model = new AbuseIPDBChecker();
        $model->setNodes($this->request->getPost('abuseipdbchecker'));
        $validationMessages = $model->performValidation();

        if (count($validationMessages) > 0) {
            return [
                'result' => 'failed',
                'validations' => $validationMessages
            ];
        }

        // Save model after validation
        $model->serializeToConfig();
        Config::getInstance()->save();

        return [
            'result' => 'saved'
        ];
    }

    /**
     * Execute plugin checks manually
     * @return array
     */
    public function runAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun('abuseipdbchecker.run');

        return [
            'result' => $response
        ];
    }

    /**
     * Get statistics about checked IPs and threats
     * @return array
     */
    public function statsAction()
    {
        $backend = new Backend();
        $response = json_decode($backend->configdRun('abuseipdbchecker.stats'), true);

        return [
            'result' => 'ok',
            'stats' => $response
        ];
    }

    /**
     * Get recent threats from the database
     * @return array
     */
    public function threatsAction()
    {
        $backend = new Backend();
        $response = json_decode($backend->configdRun('abuseipdbchecker.threats'), true);

        return [
            'result' => 'ok',
            'threats' => $response
        ];
    }
}