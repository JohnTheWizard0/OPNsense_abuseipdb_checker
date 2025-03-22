<?php

/**
 *    Copyright (C) 2023 Your Name
 *
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 *
 */

namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 * @package OPNsense\AbuseIPDBChecker\Api
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\AbuseIPDBChecker\AbuseIPDBChecker';
    protected static $internalServiceTemplate = 'OPNsense/AbuseIPDBChecker';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'abuseipdbchecker';

    /**
     * reconfigure AbuseIPDBChecker
     */
    public function reloadAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            $backend = new Backend();
            
            // Check if model data exists in config
            $configObj = Config::getInstance()->object();
            $modelPath = 'OPNsense.abuseipdbchecker';
            
            if (!isset($configObj->OPNsense) || !isset($configObj->OPNsense->abuseipdbchecker)) {
                // Configuration doesn't exist yet, force create it
                $model = new \OPNsense\AbuseIPDBChecker\AbuseIPDBChecker();
                $model->general->Enabled = 1; // Force enable
                $model->serializeToConfig();
                
                // Save config
                Config::getInstance()->save();
            }
            
            // Now reload template
            $status = strtolower(trim($backend->configdRun('template reload OPNsense/AbuseIPDBChecker')));
            
            if ($status == "ok") {
                // Ensure directory exists
                if (!file_exists('/usr/local/etc/abuseipdbchecker')) {
                    mkdir('/usr/local/etc/abuseipdbchecker', 0755, true);
                }
            }
        }
        return ["status" => $status];
    }

    /**
     * get logs
     */
    public function logsAction()
    {
        $backend = new Backend();
        $bckresult = json_decode(trim($backend->configdRun("abuseipdbchecker logs")), true);
        if ($bckresult !== null) {
            return $bckresult;
        }
        return ["message" => "Unable to retrieve logs"];
    }

    /**
     * run a manual check
     */
    public function checkAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $bckresult = json_decode(trim($backend->configdRun("abuseipdbchecker check")), true);
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["message" => "Unable to run manual check"];
    }

    /**
     * initialize database
     */
    public function initdbAction()
    {
        if ($this->request->isPost()) {
            $backend = new Backend();
            $bckresult = json_decode(trim($backend->configdRun("abuseipdbchecker initdb")), true);
            if ($bckresult !== null) {
                return $bckresult;
            }
        }
        return ["message" => "Unable to initialize database"];
    }

    /**
     * get statistics
     */
    public function statsAction()
    {
        $backend = new Backend();
        $bckresult = json_decode(trim($backend->configdRun("abuseipdbchecker stats")), true);
        if ($bckresult !== null) {
            return $bckresult;
        }
        return ["message" => "Unable to retrieve statistics"];
    }

    /**
     * get recent threats
     */
    public function threatsAction()
    {
        $backend = new Backend();
        $bckresult = json_decode(trim($backend->configdRun("abuseipdbchecker threats")), true);
        if ($bckresult !== null) {
            return $bckresult;
        }
        return ["message" => "Unable to retrieve recent threats"];
    }

    protected function reconfigureForceRestart()
    {
        return 0;
    }
}