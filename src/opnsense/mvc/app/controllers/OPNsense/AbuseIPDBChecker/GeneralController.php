<?php

/**
 * AbuseIPDB Checker UI Controller
 */

namespace OPNsense\AbuseIPDBChecker;

use OPNsense\Base\IndexController;
use OPNsense\Core\Config;
use OPNsense\AbuseIPDBChecker\AbuseIPDBChecker;

class GeneralController extends IndexController
{
    /**
     * Main index page
     * @return view
     */
    public function indexAction()
    {
        // Render the main index view
        $this->view->pick('OPNsense/AbuseIPDBChecker/index');
        
        // Load form data - this is key for populating the form
        $this->view->generalForm = $this->getForm("general");
    }
}