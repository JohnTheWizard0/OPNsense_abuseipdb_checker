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

        // Load logs
        function loadLogs() {
            ajaxCall(url="/api/abuseipdbchecker/service/logs", sendData={}, callback=function(data) {
                if (data && data.status === 'ok' && data.logs) {
                    var logContent = "";
                    if (data.logs.length === 0) {
                        logContent = "No log entries found.";
                    } else {
                        // Join the log entries with proper line breaks
                        logContent = data.logs.join('\n');
                    }
                    $("#log-content").text(logContent);
                } else {
                    // Display the specific error message from the backend
                    $("#log-content").text(data.message || "Error retrieving logs. Check permissions on /var/log/abuseipdbchecker/.");
                }
            });
        }

        // Test IP button handler
        $("#testIpBtn").click(function() {
            var ip = $("#ipToTest").val().trim();
            if (!ip) {
                $("#testResultAlert").removeClass("hidden alert-success alert-danger alert-warning")
                    .addClass("alert-warning")
                    .text("Please enter an IP address");
                $("#testResults").removeClass("hidden");
                $("#testResultTable").addClass("hidden");
                return;
            }
            
            // Validate IP format with regex
            var ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
            if (!ipRegex.test(ip)) {
                $("#testResultAlert").removeClass("hidden alert-success alert-danger alert-warning")
                    .addClass("alert-danger")
                    .text("Invalid IP address format");
                $("#testResults").removeClass("hidden");
                $("#testResultTable").addClass("hidden");
                return;
            }
            
            // Show loading
            $("#testIpBtn").prop("disabled", true);
            $("#testResultAlert").removeClass("hidden alert-success alert-danger alert-warning")
                .addClass("alert-info")
                .text("Testing IP address...");
            $("#testResults").removeClass("hidden");
            $("#testResultTable").addClass("hidden");
            
            // Make AJAX call
            ajaxCall(
                url="/api/abuseipdbchecker/service/testip",
                sendData={"ip": ip},
                callback=function(data) {
                    $("#testIpBtn").prop("disabled", false);
                    
                    if (data && data.status === 'ok') {
                        // Show results
                        $("#testResultAlert").removeClass("alert-info alert-danger alert-warning")
                            .addClass(data.is_threat ? "alert-danger" : "alert-success")
                            .text(data.is_threat ? 
                                "Malicious IP detected with score " + data.abuse_score + "%" : 
                                "IP appears to be safe with score " + data.abuse_score + "%");
                        
                        // Fill in the table
                        $("#result-ip").text(data.ip);
                        $("#result-threat").html(data.is_threat ? 
                            '<span class="label label-danger">Malicious</span>' : 
                            '<span class="label label-success">Safe</span>');
                        $("#result-score").text(data.abuse_score + "%");
                        $("#result-country").text(data.country);
                        $("#result-isp").text(data.isp);
                        $("#result-domain").text(data.domain);
                        $("#result-reports").text(data.reports);
                        $("#result-last-reported").text(data.last_reported);
                        
                        $("#testResultTable").removeClass("hidden");
                        
                        // Refresh statistics and threats
                        loadStats();
                        loadThreats();
                        loadLogs();
                    } else {
                        // Show error
                        $("#testResultAlert").removeClass("alert-info alert-success alert-warning")
                            .addClass("alert-danger")
                            .text(data.message || "Error testing IP address");
                        $("#testResultTable").addClass("hidden");
                    }
                }
            );
        });

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
    });
</script>

<div class="alert hidden" role="alert" id="statusMsg"></div>

<ul class="nav nav-tabs" role="tablist">
    <li class="active"><a data-toggle="tab" href="#general">General</a></li>
    <li><a data-toggle="tab" href="#network">Network</a></li>
    <li><a data-toggle="tab" href="#api">API</a></li>
    <li><a data-toggle="tab" href="#email">Email</a></li>
    <li><a data-toggle="tab" href="#testip">Test IP</a></li>
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
    <div id="testip" class="tab-pane fade">
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
                        </tbody>
                    </table>
                </div>
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