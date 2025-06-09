<!-- Main Settings Tabs -->
<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#network">{{ lang._('Network') }}</a></li>
    <li><a data-toggle="tab" href="#api">{{ lang._('API') }}</a></li>
    <li><a data-toggle="tab" href="#alias">{{ lang._('Alias') }}</a></li>
    <li><a data-toggle="tab" href="#testip">{{ lang._('Test IP') }}</a></li>
    <li><a data-toggle="tab" href="#ntfy">{{ lang._('ntfy') }}</a></li>
</ul>

<div class="tab-content content-box">
    {{ partial("OPNsense/AbuseIPDBChecker/partials/tabs/general") }}
    {{ partial("OPNsense/AbuseIPDBChecker/partials/tabs/network") }}
    {{ partial("OPNsense/AbuseIPDBChecker/partials/tabs/api") }}
    {{ partial("OPNsense/AbuseIPDBChecker/partials/tabs/alias") }}
    {{ partial("OPNsense/AbuseIPDBChecker/partials/tabs/testip") }}
    {{ partial("OPNsense/AbuseIPDBChecker/partials/tabs/ntfy") }}
    
    <!-- Save Button -->
    <div class="col-md-12">
        <button class="btn btn-primary" id="saveAct" type="button">
            <b>{{ lang._('Save') }}</b> <i id="saveAct_progress" class=""></i>
        </button>
    </div>
</div>

<!-- Service Control Section -->
{{ partial("OPNsense/AbuseIPDBChecker/partials/components/service-controls") }}

<!-- Enhanced Statistics & Monitoring Section -->
{{ partial("OPNsense/AbuseIPDBChecker/partials/components/monitoring-tabs") }}

<!-- Include Styles -->
{{ partial("OPNsense/AbuseIPDBChecker/partials/styles/main") }}

<!-- Include Scripts -->
{{ partial("OPNsense/AbuseIPDBChecker/partials/scripts/main") }}

