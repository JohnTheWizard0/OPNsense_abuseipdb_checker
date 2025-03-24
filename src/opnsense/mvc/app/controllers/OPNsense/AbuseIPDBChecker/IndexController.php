<?php
namespace OPNsense\AbuseIPDBChecker;

use OPNsense\Base\IndexController as BaseIndexController;

class IndexController extends BaseIndexController
{
    public function indexAction()
    {
        // Load model for validation
        $this->view->setTemplate('OPNsense/AbuseIPDBChecker/index');
        $this->view->generalForm = $this->getForm("general");
        $this->view->networkForm = $this->getForm("network");
        $this->view->apiForm = $this->getForm("api");
        $this->view->emailForm = $this->getForm("email");
    }
}