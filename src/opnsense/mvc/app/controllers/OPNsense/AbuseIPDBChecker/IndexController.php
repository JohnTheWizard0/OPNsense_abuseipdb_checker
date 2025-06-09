<?php
namespace OPNsense\AbuseIPDBChecker;

use OPNsense\Base\IndexController as BaseIndexController;

class IndexController extends BaseIndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/AbuseIPDBChecker/index');
        $this->view->generalForm = $this->getForm("general");
        $this->view->networkForm = $this->getForm("network");
        $this->view->apiForm = $this->getForm("api");
        $this->view->aliasForm = $this->getForm("alias");
        $this->view->ntfyForm = $this->getForm("ntfy");
    }
}