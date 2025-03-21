<!-- AbuseIPDB Checker Settings -->
<div id="abuseipdbchecker-settings" class="tab-pane" data-toggle="form">
    <!-- Add a hidden form that OPNsense can bind to -->
    <form id="frm_GeneralSettings">
        <div class="content-box">
            <div class="content-box-main">
                <div class="table-responsive">
                    <!-- General Settings -->
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th colspan="2">{{ lang._('General Settings') }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><a id="help_for_general.enabled" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Enable Plugin') }}</td>
                                <td>
                                    <input id="general.enabled" name="general.enabled" type="checkbox" class="form-control"/>
                                    <div class="hidden" data-for="help_for_general.enabled">
                                        <small>{{ lang._('Enable or disable the AbuseIPDB Checker plugin.') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_general.checkFrequency" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Check Frequency (days)') }}</td>
                                <td>
                                    <input id="general.checkFrequency" name="general.checkFrequency" type="number" min="1" max="30" class="form-control"/>
                                    <div class="hidden" data-for="help_for_general.checkFrequency">
                                        <small>{{ lang._('Number of days to wait before rechecking an IP address.') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_general.abuseScoreThreshold" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Abuse Score Threshold') }}</td>
                                <td>
                                    <input id="general.abuseScoreThreshold" name="general.abuseScoreThreshold" type="number" min="1" max="100" class="form-control"/>
                                    <div class="hidden" data-for="help_for_general.abuseScoreThreshold">
                                        <small>{{ lang._('Minimum confidence score (1-100) to consider an IP a potential threat.') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_general.dailyCheckLimit" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Daily Check Limit') }}</td>
                                <td>
                                    <input id="general.dailyCheckLimit" name="general.dailyCheckLimit" type="number" min="1" max="1000" class="form-control"/>
                                    <div class="hidden" data-for="help_for_general.dailyCheckLimit">
                                        <small>{{ lang._('Maximum number of IPs to check per day. Helps manage API usage.') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_general.ignoreBlockedConnections" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Ignore Blocked Connections') }}</td>
                                <td>
                                    <input id="general.ignoreBlockedConnections" name="general.ignoreBlockedConnections" type="checkbox" class="form-control"/>
                                    <div class="hidden" data-for="help_for_general.ignoreBlockedConnections">
                                        <small>{{ lang._('When enabled, only monitor allowed connections and ignore blocked traffic.') }}</small>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                    
                    <!-- Network Settings -->
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th colspan="2">{{ lang._('Network Settings') }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><a id="help_for_network.lanSubnets" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('LAN Subnets') }}</td>
                                <td>
                                    <input id="network.lanSubnets" name="network.lanSubnets" type="text" class="form-control"/>
                                    <div class="hidden" data-for="help_for_network.lanSubnets">
                                        <small>{{ lang._('Comma-separated list of LAN subnets to monitor in CIDR notation (e.g., 192.168.0.0/16,10.0.0.0/8).') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_network.ignoreProtocols" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Ignore Protocols') }}</td>
                                <td>
                                    <input id="network.ignoreProtocols" name="network.ignoreProtocols" type="text" class="form-control"/>
                                    <div class="hidden" data-for="help_for_network.ignoreProtocols">
                                        <small>{{ lang._('Comma-separated list of protocols to ignore (e.g., icmp,igmp).') }}</small>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                    
                    <!-- API Settings -->
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th colspan="2">{{ lang._('AbuseIPDB API Settings') }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><a id="help_for_api.key" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('API Key') }}</td>
                                <td>
                                    <input id="api.key" name="api.key" type="text" class="form-control"/>
                                    <div class="hidden" data-for="help_for_api.key">
                                        <small>{{ lang._('Your AbuseIPDB API key. Sign up at https://www.abuseipdb.com/ to get one.') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <!-- Inside the API Settings table, add this after the API Key row -->
                            <tr>
                                <td><a id="help_for_api.endpoint" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('API Endpoint') }}</td>
                                <td>
                                    <input id="api.endpoint" name="api.endpoint" type="text" class="form-control"/>
                                    <div class="hidden" data-for="help_for_api.endpoint">
                                        <small>{{ lang._('AbuseIPDB API endpoint URL. Default format is https://www.abuseipdb.com/check/[IP]/json') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_api.maxAge" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Max Age (days)') }}</td>
                                <td>
                                    <input id="api.maxAge" name="api.maxAge" type="number" min="1" max="365" class="form-control"/>
                                    <div class="hidden" data-for="help_for_api.maxAge">
                                        <small>{{ lang._('Maximum age in days for IP reports to consider.') }}</small>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                    
                    <!-- Email Settings -->
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th colspan="2">{{ lang._('Email Notification Settings') }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><a id="help_for_email.enabled" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Enable Email Notifications') }}</td>
                                <td>
                                    <input id="email.enabled" name="email.enabled" type="checkbox" class="form-control"/>
                                    <div class="hidden" data-for="help_for_email.enabled">
                                        <small>{{ lang._('Enable or disable email notifications for potential threats.') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_email.smtpServer" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('SMTP Server') }}</td>
                                <td>
                                    <input id="email.smtpServer" name="email.smtpServer" type="text" class="form-control"/>
                                    <div class="hidden" data-for="help_for_email.smtpServer">
                                        <small>{{ lang._('SMTP server address for sending email notifications.') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_email.smtpPort" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('SMTP Port') }}</td>
                                <td>
                                    <input id="email.smtpPort" name="email.smtpPort" type="number" min="1" max="65535" class="form-control"/>
                                    <div class="hidden" data-for="help_for_email.smtpPort">
                                        <small>{{ lang._('SMTP server port (usually 25, 465, or 587).') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_email.smtpUsername" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('SMTP Username') }}</td>
                                <td>
                                    <input id="email.smtpUsername" name="email.smtpUsername" type="text" class="form-control"/>
                                    <div class="hidden" data-for="help_for_email.smtpUsername">
                                        <small>{{ lang._('Username for SMTP authentication (optional).') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_email.smtpPassword" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('SMTP Password') }}</td>
                                <td>
                                    <input id="email.smtpPassword" name="email.smtpPassword" type="password" class="form-control"/>
                                    <div class="hidden" data-for="help_for_email.smtpPassword">
                                        <small>{{ lang._('Password for SMTP authentication (optional).') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_email.fromAddress" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('From Email Address') }}</td>
                                <td>
                                    <input id="email.fromAddress" name="email.fromAddress" type="text" class="form-control"/>
                                    <div class="hidden" data-for="help_for_email.fromAddress">
                                        <small>{{ lang._('Sender email address for notifications.') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_email.toAddress" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('To Email Address') }}</td>
                                <td>
                                    <input id="email.toAddress" name="email.toAddress" type="text" class="form-control"/>
                                    <div class="hidden" data-for="help_for_email.toAddress">
                                        <small>{{ lang._('Recipient email address for notifications.') }}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td><a id="help_for_email.useTLS" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Use TLS') }}</td>
                                <td>
                                    <input id="email.useTLS" name="email.useTLS" type="checkbox" class="form-control"/>
                                    <div class="hidden" data-for="help_for_email.useTLS">
                                        <small>{{ lang._('Enable TLS encryption for SMTP communication.') }}</small>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <div class="col-md-12">
                    <hr/>
                    <button class="btn btn-primary" id="saveAct" type="button"><b>{{ lang._('Save') }}</b></button>
                    <button class="btn btn-info" id="runAct" type="button"><b>{{ lang._('Run Now') }}</b></button>
                </div>
            </div>
        </div>
    </form>
    
    <!-- Statistics & Threats Tabs -->
    <div class="content-box">
        <ul class="nav nav-tabs" data-tabs="tabs" id="abuseipdb-tabs">
            <li class="active"><a data-toggle="tab" href="#stats">{{ lang._('Statistics') }}</a></li>
            <li><a data-toggle="tab" href="#threats">{{ lang._('Recent Threats') }}</a></li>
            <li><a data-toggle="tab" href="#logs">{{ lang._('Logs') }}</a></li>
        </ul>
        <div class="tab-content content-box-main">
            <!-- Statistics Tab -->
            <div id="stats" class="tab-pane active">
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
                            <td>{{ lang._('Total Threats Detected') }}</td>
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
            
            <!-- Recent Threats Tab -->
            <div id="threats" class="tab-pane">
                <table class="table table-striped table-condensed">
                    <thead>
                        <tr>
                            <th>{{ lang._('IP Address') }}</th>
                            <th>{{ lang._('Score') }}</th>
                            <th>{{ lang._('Last Checked') }}</th>
                            <th>{{ lang._('Country') }}</th>
                            <th>{{ lang._('Details') }}</th>
                        </tr>
                    </thead>
                    <tbody id="recent-threats-table">
                        <!-- Dynamically populated -->
                    </tbody>
                </table>
            </div>
            
            <!-- Logs Tab -->
            <div id="logs" class="tab-pane">
                <div class="row">
                    <div class="col-md-12">
                        <button class="btn btn-sm btn-info pull-right" id="refreshLogsBtn">
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

<script>
    $(document).ready(function() {
        // Load initial data
        mapDataToFormUI({'frm_GeneralSettings':"/api/abuseipdbchecker/settings/get"}).done(function(data){
            // place actions to run after load, for example update form styles.
            updateStats();
            updateThreats();
        });

        // link save button to API set action
        $("#saveAct").click(function(){
            saveFormToEndpoint("/api/abuseipdbchecker/settings/set", 'frm_GeneralSettings', function(){
                // action to run after successful save, for example reconfigure service.
                ajaxCall(url="/api/abuseipdbchecker/service/reconfigure", sendData={}, callback=function(data,status) {
                    // Update stats after reconfigure
                    updateStats();
                    updateThreats();
                });
            });
        });

        // Run now button
        $("#runAct").SimpleActionButton({
            onPreAction: function() {
                // Set button to loading state
                return true;
            },
            onAction: function(data) {
                // Update stats and threats
                updateStats();
                updateThreats();
            }
        });

        // Refresh logs button
        $("#refreshLogsBtn").click(function() {
            updateLogs();
        });

        // Update statistics
        function updateStats() {
            ajaxCall(
                "/api/abuseipdbchecker/settings/stats",
                {},
                function(data, status) {
                    if (data.stats) {
                        $("#total-ips-checked").text(data.stats.total_checked || 0);
                        $("#total-threats").text(data.stats.total_threats || 0);
                        $("#checks-today").text(data.stats.checks_today || 0);
                        $("#last-run").text(data.stats.last_run || 'Never');
                    }
                }
            );
        }

        // Update threats list
        function updateThreats() {
            ajaxCall(
                "/api/abuseipdbchecker/settings/threats",
                {},
                function(data, status) {
                    var threats = data.threats || [];
                    var table = $("#recent-threats-table");
                    table.empty();
                    
                    if (threats.length === 0) {
                        table.append('<tr><td colspan="5">{{ lang._("No threats detected") }}</td></tr>');
                    } else {
                        threats.forEach(function(threat) {
                            var row = '<tr>' +
                                '<td>' + threat.ip + '</td>' +
                                '<td>' + threat.score + '%</td>' +
                                '<td>' + threat.last_checked + '</td>' +
                                '<td>' + (threat.country || 'Unknown') + '</td>' +
                                '<td><a href="https://www.abuseipdb.com/check/' + threat.ip + '" target="_blank">' +
                                '<i class="fa fa-external-link"></i></a></td>' +
                                '</tr>';
                            table.append(row);
                        });
                    }
                }
            );
        }

        // Update logs function
        function updateLogs() {
            var refreshBtn = $("#refreshLogsBtn");
            refreshBtn.prop('disabled', true);
            refreshBtn.html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Loading...") }}');
            
            ajaxCall(
                "/api/abuseipdbchecker/settings/logs",
                {},
                function(data, status) {
                    if (data && data.result === 'ok') {
                        var logContentDiv = $("#log-content");
                        logContentDiv.empty();
                        
                        if (data.logs && data.logs.length > 0) {
                            // Process and colorize log entries
                            var logHtml = '';
                            data.logs.forEach(function(logEntry) {
                                var colorClass = '';
                                if (logEntry.toLowerCase().includes('error')) {
                                    colorClass = 'text-danger';
                                } else if (logEntry.toLowerCase().includes('warning')) {
                                    colorClass = 'text-warning';
                                } else if (logEntry.toLowerCase().includes('threat')) {
                                    colorClass = 'text-danger';
                                } else if (logEntry.toLowerCase().includes('check')) {
                                    colorClass = 'text-info';
                                }
                                
                                logHtml += '<div class="' + colorClass + '">' + escapeHtml(logEntry) + '</div>';
                            });
                            
                            logContentDiv.html(logHtml);
                            
                            // Scroll to the bottom of the log container
                            var logContainer = $(".log-container");
                            logContainer.scrollTop(logContainer.prop('scrollHeight'));
                        } else {
                            logContentDiv.html('<span class="text-muted">{{ lang._("No log entries found") }}</span>');
                        }
                    } else {
                        $("#log-content").html('<span class="text-danger">{{ lang._("Error loading logs") }}</span>');
                    }
                    
                    // Reset button
                    refreshBtn.prop('disabled', false);
                    refreshBtn.html('<i class="fa fa-refresh"></i> {{ lang._("Refresh") }}');
                }
            );
        }

        // Helper function to escape HTML
        function escapeHtml(unsafe) {
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // Load logs when the tab is shown
        $('a[data-toggle="tab"]').on('shown.bs.tab', function(e) {
            if ($(e.target).attr('href') === '#logs') {
                updateLogs();
            }
        });
    });
</script>