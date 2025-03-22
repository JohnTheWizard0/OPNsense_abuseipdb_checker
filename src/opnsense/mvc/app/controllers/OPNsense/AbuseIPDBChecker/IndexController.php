<?php
namespace OPNsense\AbuseIPDBChecker;

use OPNsense\Base\IndexController as BaseIndexController;

class IndexController extends BaseIndexController
{
    public function indexAction()
    {
        // Just render the view
        $this->view->pick('OPNsense/AbuseIPDBChecker/index');
    }
}