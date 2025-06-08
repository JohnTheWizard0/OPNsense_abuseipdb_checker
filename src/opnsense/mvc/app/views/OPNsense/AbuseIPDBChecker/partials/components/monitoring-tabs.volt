<!-- Enhanced Statistics & Monitoring Section -->
<div class="content-box" style="margin-top: 20px;">
    <ul class="nav nav-tabs" data-tabs="tabs" id="abuseipdb-tabs">
        <li class="active"><a data-toggle="tab" href="#stats">{{ lang._('Statistics') }}</a></li>
        <li><a data-toggle="tab" href="#externalips">{{ lang._('External IPs') }}</a></li>
        <li><a data-toggle="tab" href="#allscannedips">{{ lang._('All Scanned IPs') }}</a></li>
        <li><a data-toggle="tab" href="#threats">{{ lang._('Recent Threats') }}</a></li>
        <li><a data-toggle="tab" href="#logs">{{ lang._('Logs') }}</a></li>
    </ul>
    <div class="tab-content content-box-main">
        <!-- Statistics Tab -->
        <div id="stats" class="tab-pane fade in active">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-12">
                        <button id="refreshStats" class="btn btn-xs btn-primary pull-right">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <table class="table table-striped table-condensed">
                            <thead>
                                <tr>
                                    <th colspan="2">{{ lang._('Usage Statistics') }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>{{ lang._('Total IPs Checked') }}</td>
                                    <td id="total-ips-checked">0</td>
                                </tr>
                                <tr>
                                    <td>{{ lang._('Total Threats Detected') }} <i class="fa fa-info-circle" title="Counts threats included in MaliciousIPs alias based on current settings"></i></td>
                                    <td id="total-threats">0</td>
                                </tr>
                                <tr>
                                    <td>{{ lang._('Checks Today') }}</td>
                                    <td id="checks-today">0</td>
                                </tr>
                                <tr>
                                    <td>{{ lang._('Last Run') }}</td>
                                    <td id="last-run">Never</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- External IPs Tab -->
        <div id="externalips" class="tab-pane fade">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-12">
                        <button id="refreshExternalIPs" class="btn btn-xs btn-primary pull-right">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                        <p class="text-muted">{{ lang._('External IPs detected from firewall logs based on current configuration') }}</p>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <div id="external-ips-info" class="alert alert-info" style="display: none;">
                            {{ lang._('Loading external IPs...') }}
                        </div>
                        <table class="table table-striped table-condensed">
                            <thead>
                                <tr>
                                    <th>{{ lang._('IP Address') }}</th>
                                    <th>{{ lang._('Previously Checked') }}</th>
                                    <th>{{ lang._('Status') }}</th>
                                    <th>{{ lang._('Last Checked') }}</th>
                                    <th>{{ lang._('Actions') }}</th>
                                </tr>
                            </thead>
                            <tbody id="external-ips-table">
                                <!-- Dynamically populated -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Enhanced All Scanned IPs Tab -->
        <div id="allscannedips" class="tab-pane fade">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-6">
                        <div class="search-container">
                            <input type="text" id="allips-search" class="form-control" placeholder="{{ lang._('Search by IP address...') }}">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <button id="refreshAllScannedIPs" class="btn btn-xs btn-primary pull-right">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                        <p class="text-muted">{{ lang._('All IPs checked against AbuseIPDB with connection details') }}</p>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <div id="all-scanned-ips-info" class="alert alert-info" style="display: none;">
                            {{ lang._('Loading all scanned IPs...') }}
                        </div>
                        <table class="table table-striped table-condensed">
                            <thead>
                                <tr>
                                    <th>{{ lang._('IP Address') }} <i class="fa fa-info-circle text-muted" title="Click info button next to IP to view connection details"></i></th>
                                    <th>{{ lang._('Status') }}</th>
                                    <th>{{ lang._('Last Checked') }}</th>
                                    <th>{{ lang._('Country') }}</th>
                                    <th>{{ lang._('Reports') }}</th>
                                    <th>{{ lang._('Actions') }}</th>
                                </tr>
                            </thead>
                            <tbody id="all-scanned-ips-table">
                                <!-- Dynamically populated -->
                            </tbody>
                        </table>
                        <div id="allips-pagination"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Enhanced Recent Threats Tab -->
        <div id="threats" class="tab-pane fade">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-6">
                        <div class="search-container">
                            <input type="text" id="threats-search" class="form-control" placeholder="{{ lang._('Search by IP address...') }}">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <button id="refreshThreats" class="btn btn-xs btn-primary pull-right">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                        <p class="text-muted">{{ lang._('Malicious IPs detected by AbuseIPDB checks with management options') }}</p>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <div id="threats-info" class="alert alert-info" style="display: none;">
                            {{ lang._('Loading threats...') }}
                        </div>
                        <table class="table table-striped table-condensed">
                            <thead>
                                <tr>
                                    <th>{{ lang._('IP Address') }} <i class="fa fa-info-circle text-muted" title="Click info button next to IP to view connection details"></i></th>
                                    <th>{{ lang._('Status') }}</th>
                                    <th>{{ lang._('Last Checked') }}</th>
                                    <th>{{ lang._('Country') }}</th>
                                    <th>{{ lang._('Reports') }}</th>
                                    <th>{{ lang._('Actions') }}</th>
                                </tr>
                            </thead>
                            <tbody id="recent-threats-table">
                                <!-- Dynamically populated -->
                            </tbody>
                        </table>
                        <div id="threats-pagination"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Logs Tab -->
        <div id="logs" class="tab-pane fade">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-12">
                        <button id="refreshLogs" class="btn btn-xs btn-primary pull-right">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <div class="log-container" style="height: 400px; overflow-y: scroll; margin-top: 10px; background-color: #f5f5f5; padding: 10px; font-family: monospace; font-size: 12px;">
                            <pre id="log-content" style="white-space: pre-wrap;"></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>