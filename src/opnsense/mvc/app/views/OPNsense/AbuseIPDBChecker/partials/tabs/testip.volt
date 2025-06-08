<!-- Test IP Tab -->
<div id="testip" class="tab-pane fade">
    <div class="container-fluid">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">{{ lang._('Test IP Address') }}</h3>
            </div>
            <div class="panel-body">
                <form id="testIpForm">
                    <div class="form-group">
                        <label for="ipToTest">{{ lang._('IP Address') }}</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="ipToTest" placeholder="Enter IP address to test" value="118.76.192.54">
                            <span class="input-group-btn">
                                <button class="btn btn-primary" type="button" id="testIpBtn">
                                    {{ lang._('Test') }}
                                </button>
                            </span>
                        </div>
                    </div>
                </form>
                
                <div id="testResults" class="hidden">
                    <div class="alert" id="testResultAlert" role="alert"></div>
                    
                    <table class="table table-striped table-condensed" id="testResultTable">
                        <tbody>
                            <tr><th>{{ lang._('IP Address') }}</th><td id="result-ip"></td></tr>
                            <tr><th>{{ lang._('Threat Status') }}</th><td id="result-threat"></td></tr>
                            <tr><th>{{ lang._('Abuse Score') }}</th><td id="result-score"></td></tr>
                            <tr><th>{{ lang._('Country') }}</th><td id="result-country"></td></tr>
                            <tr><th>{{ lang._('ISP') }}</th><td id="result-isp"></td></tr>
                            <tr><th>{{ lang._('Domain') }}</th><td id="result-domain"></td></tr>
                            <tr><th>{{ lang._('Reports') }}</th><td id="result-reports"></td></tr>
                            <tr><th>{{ lang._('Last Reported') }}</th><td id="result-last-reported"></td></tr>
                            <tr><th>{{ lang._('AbuseIPDB Report') }}</th><td id="result-abusedb-link"></td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>