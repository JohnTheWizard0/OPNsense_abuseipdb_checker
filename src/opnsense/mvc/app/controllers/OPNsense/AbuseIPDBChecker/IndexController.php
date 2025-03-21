<?php


namespace OPNsense\AbuseIPDBChecker;

/**
 * Class IndexController
 * @package OPNsense\AbuseIPDBChecker
 */
class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        // pick the template to serve to our users.
        $this->view->pick('OPNsense/AbuseIPDBChecker/index');
        // fetch form data
        $this->view->generalForm = $this->getForm("general");
    }
}