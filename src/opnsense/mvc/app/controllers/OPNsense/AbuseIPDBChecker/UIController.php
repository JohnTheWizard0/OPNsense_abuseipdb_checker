<?php

/**
 * AbuseIPDB Checker UI Controller
 */

namespace OPNsense\AbuseIPDBChecker;

use OPNsense\Base\UIController;
use OPNsense\Core\Config;
use OPNsense\AbuseIPDBChecker\AbuseIPDBChecker;

class UIController extends UIController
{
    /**
     * Main index page
     * @return view
     */
    public function indexAction()
    {
        // Render the main index view
        $this->view->pick('OPNsense/AbuseIPDBChecker/index');
    }
}