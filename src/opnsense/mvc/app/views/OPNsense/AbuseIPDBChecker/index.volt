<script>
    $( document ).ready(function() {
        mapDataToFormUI({'frm_GeneralSettings':"/api/abuseipdbchecker/settings/get"}).done(function(data){
            // place actions to run after load, for example update form styles.
        });

        
        // Simple direct AJAX call to get settings
        ajaxCall(url="/api/abuseipdbchecker/settings/get", sendData={}, callback=function(data) {
            console.log("Settings data:", data);
            if (data && data.abuseipdbchecker) {
                var conf = data.abuseipdbchecker;
                
                // Populate form fields with configuration values
                if (conf.general) {
                    $("#enabled").prop('checked', conf.general.Enabled === '1');
                    $("#logfile").val(conf.general.LogFile);
                    $("#checkfrequency").val(conf.general.CheckFrequency);
                    $("#abusethreshold").val(conf.general.AbuseScoreThreshold);
                    $("#dailylimit").val(conf.general.DailyCheckLimit);
                    $("#ignoreblocked").prop('checked', conf.general.IgnoreBlockedConnections === '1');
                }
                
                if (conf.api) {
                    $("#apikey").val(conf.api.Key);
                    $("#endpoint").val(conf.api.Endpoint);
                    $("#maxage").val(conf.api.MaxAge);
                }
                
                if (conf.network) {
                    $("#lansubnets").val(conf.network.LanSubnets);
                    $("#ignoreprotocols").val(conf.network.IgnoreProtocols);
                }
                
                if (conf.email) {
                    $("#emailenabled").prop('checked', conf.email.Enabled === '1');
                    $("#smtpserver").val(conf.email.SmtpServer);
                    $("#smtpport").val(conf.email.SmtpPort);
                    $("#smtpuser").val(conf.email.SmtpUsername);
                    $("#smtppass").val(conf.email.SmtpPassword);
                    $("#fromemail").val(conf.email.FromAddress);
                    $("#toemail").val(conf.email.ToAddress);
                    $("#usetls").prop('checked', conf.email.UseTLS === '1');
                }
            }
        });
        
        // Save button handler
        $("#saveBtn").click(function() {
            // Collect form data
            var formData = {
                abuseipdbchecker: {
                    general: {
                        Enabled: $("#enabled").prop('checked') ? '1' : '0',
                        LogFile: $("#logfile").val(),
                        CheckFrequency: $("#checkfrequency").val(),
                        AbuseScoreThreshold: $("#abusethreshold").val(),
                        DailyCheckLimit: $("#dailylimit").val(),
                        IgnoreBlockedConnections: $("#ignoreblocked").prop('checked') ? '1' : '0'
                    },
                    network: {
                        LanSubnets: $("#lansubnets").val(),
                        IgnoreProtocols: $("#ignoreprotocols").val()
                    },
                    api: {
                        Key: $("#apikey").val(),
                        Endpoint: $("#endpoint").val(),
                        MaxAge: $("#maxage").val()
                    },
                    email: {
                        Enabled: $("#emailenabled").prop('checked') ? '1' : '0',
                        SmtpServer: $("#smtpserver").val(),
                        SmtpPort: $("#smtpport").val(),
                        SmtpUsername: $("#smtpuser").val(),
                        SmtpPassword: $("#smtppass").val(),
                        FromAddress: $("#fromemail").val(),
                        ToAddress: $("#toemail").val(),
                        UseTLS: $("#usetls").prop('checked') ? '1' : '0'
                    }
                }
            };
            
            // Load statistics
            function loadStats() {
                ajaxCall(url="/api/abuseipdbchecker/service/stats", sendData={}, callback=function(data) {
                    if (data && data.status === 'ok') {
                        $("#total-ips-checked").text(data.total_ips || 0);
                        $("#total-threats").text(data.total_threats || 0);
                        $("#checks-today").text(data.daily_checks || 0);
                        $("#last-run").text(data.last_check || 'Never');
                    }
                });
            }

            // Load recent threats
            function loadThreats() {
                ajaxCall(url="/api/abuseipdbchecker/service/threats", sendData={}, callback=function(data) {
                    if (data && data.status === 'ok' && data.threats) {
                        var threatTable = $("#recent-threats-table");
                        threatTable.empty();
                        
                        if (data.threats.length === 0) {
                            threatTable.append('<tr><td colspan="5">No threats detected</td></tr>');
                        } else {
                            $.each(data.threats, function(i, threat) {
                                var row = $('<tr>');
                                row.append($('<td>').text(threat.ip));
                                row.append($('<td>').text(threat.score + '%'));
                                row.append($('<td>').text(threat.last_seen));
                                row.append($('<td>').text(threat.country));
                                row.append($('<td>').html('<a href="https://www.abuseipdb.com/check/' + threat.ip + '" target="_blank">View</a>'));
                                threatTable.append(row);
                            });
                        }
                    }
                });
            }

            // Load logs (this will need a backend function implementation)
            function loadLogs() {
                ajaxCall(url="/api/abuseipdbchecker/service/logs", sendData={}, callback=function(data) {
                    if (data && data.status === 'ok' && data.logs) {
                        $("#log-content").text(data.logs.join(''));
                    } else {
                        $("#log-content").text("No logs available or error retrieving logs");
                    }
                });
            }

            // Initial load
            loadStats();
            loadThreats();
            loadLogs();

            // Add tab change event to refresh data
            $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
                var target = $(e.target).attr("href");
                if (target === "#stats") {
                    loadStats();
                } else if (target === "#threats") {
                    loadThreats();
                } else if (target === "#logs") {
                    loadLogs();
                }
            });

            // Add refresh button handler
            $("#refreshLogsBtn").click(function() {
                loadLogs();
            });


            // Send AJAX request
            ajaxCall(
                url="/api/abuseipdbchecker/settings/set",
                sendData=formData,
                callback=function(data) {
                    if (data && data.result === 'saved') {
                        $("#statusMsg").removeClass("hidden alert-danger").addClass("alert-success").text("Settings saved successfully.");
                    } else {
                        $("#statusMsg").removeClass("hidden alert-success").addClass("alert-danger").text("Failed to save settings.");
                    }
                }
            );
            
        });
    });
</script>

<div class="alert hidden" role="alert" id="statusMsg"></div>

<ul class="nav nav-tabs" role="tablist">
    <li class="active"><a data-toggle="tab" href="#general">General</a></li>
    <li><a data-toggle="tab" href="#network">Network</a></li>
    <li><a data-toggle="tab" href="#api">API</a></li>
    <li><a data-toggle="tab" href="#email">Email</a></li>
</ul>

<div class="tab-content">
    <div id="general" class="tab-pane fade in active">
        <div class="form-group">
            <label class="control-label">Enable AbuseIPDB Checker</label>
            <div class="checkbox">
                <label>
                    <input type="checkbox" id="enabled"> Enable service
                </label>
            </div>
        </div>
        <div class="form-group">
            <label for="logfile" class="control-label">Log File Path</label>
            <input type="text" class="form-control" id="logfile">
        </div>
        <div class="form-group">
            <label for="checkfrequency" class="control-label">Check Frequency (days)</label>
            <input type="number" class="form-control" id="checkfrequency" min="1" max="30">
        </div>
        <div class="form-group">
            <label for="abusethreshold" class="control-label">Abuse Score Threshold</label>
            <input type="number" class="form-control" id="abusethreshold" min="1" max="100">
        </div>
        <div class="form-group">
            <label for="dailylimit" class="control-label">Daily Check Limit</label>
            <input type="number" class="form-control" id="dailylimit" min="1" max="1000">
        </div>
        <div class="form-group">
            <label class="control-label">Ignore Blocked Connections</label>
            <div class="checkbox">
                <label>
                    <input type="checkbox" id="ignoreblocked"> Only monitor allowed connections
                </label>
            </div>
        </div>
    </div>
    
    <div id="network" class="tab-pane fade">
        <div class="form-group">
            <label for="lansubnets" class="control-label">LAN Subnets</label>
            <input type="text" class="form-control" id="lansubnets">
            <span class="help-block">Comma separated CIDR notation (e.g. 192.168.0.0/16,10.0.0.0/8)</span>
        </div>
        <div class="form-group">
            <label for="ignoreprotocols" class="control-label">Ignore Protocols</label>
            <input type="text" class="form-control" id="ignoreprotocols">
            <span class="help-block">Comma separated protocols to ignore (e.g. icmp,igmp)</span>
        </div>
    </div>
    
    <div id="api" class="tab-pane fade">
        <div class="form-group">
            <label for="apikey" class="control-label">API Key</label>
            <input type="text" class="form-control" id="apikey">
        </div>
        <div class="form-group">
            <label for="endpoint" class="control-label">API Endpoint</label>
            <input type="text" class="form-control" id="endpoint">
        </div>
        <div class="form-group">
            <label for="maxage" class="control-label">Max Age (days)</label>
            <input type="number" class="form-control" id="maxage" min="1" max="365">
        </div>
    </div>
    
    <div id="email" class="tab-pane fade">
        <div class="form-group">
            <label class="control-label">Enable Email Notifications</label>
            <div class="checkbox">
                <label>
                    <input type="checkbox" id="emailenabled"> Send email alerts for threats
                </label>
            </div>
        </div>
        <div class="form-group">
            <label for="smtpserver" class="control-label">SMTP Server</label>
            <input type="text" class="form-control" id="smtpserver">
        </div>
        <div class="form-group">
            <label for="smtpport" class="control-label">SMTP Port</label>
            <input type="number" class="form-control" id="smtpport">
        </div>
        <div class="form-group">
            <label for="smtpuser" class="control-label">SMTP Username</label>
            <input type="text" class="form-control" id="smtpuser">
        </div>
        <div class="form-group">
            <label for="smtppass" class="control-label">SMTP Password</label>
            <input type="password" class="form-control" id="smtppass">
        </div>
        <div class="form-group">
            <label for="fromemail" class="control-label">From Email</label>
            <input type="email" class="form-control" id="fromemail">
        </div>
        <div class="form-group">
            <label for="toemail" class="control-label">To Email</label>
            <input type="email" class="form-control" id="toemail">
        </div>
        <div class="form-group">
            <label class="control-label">Use TLS</label>
            <div class="checkbox">
                <label>
                    <input type="checkbox" id="usetls"> Enable TLS for SMTP
                </label>
            </div>
        </div>
    </div>
</div>

<div class="form-group">
    <div class="col-sm-12">
        <button class="btn btn-primary" id="saveBtn">Save Settings</button>
    </div>
</div>

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