{#
    AbuseIPDB Checker Plugin
    
    Configure and monitor IP reputation using AbuseIPDB API
#}

<script type="text/javascript">
    $( document ).ready(function() {
        // Load settings form
        mapDataToFormUI({
            'frm_GeneralSettings':"/api/abuseipdbchecker/settings/get"
        }).done(function(data){
            // Update statistics after loading form
            updateStats();
            updateThreats();
        });

        // Save settings
        $("#saveAct").click(function(){
            saveFormToEndpoint(
                url="/api/abuseipdbchecker/settings/set",
                formid='frm_GeneralSettings',
                callback_ok=function(){
                    // Reconfigure service after save
                    ajaxCall(
                        url="/api/abuseipdbchecker/service/reconfigure",
                        sendData={},
                        callback=function(data,status) {
                            // Update stats after reconfigure
                            updateStats();
                            updateThreats();
                        }
                    );
                }
            );
        });

        // Run now button
        $("#runAct").click(function() {
            // Disable button and show spinner
            $(this).prop('disabled', true);
            $(this).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Running...") }}');
            
            // Call API to run checker
            ajaxCall(
                url="/api/abuseipdbchecker/service/run",
                sendData={},
                callback=function(data,status){
                    // Re-enable button
                    $("#runAct").prop('disabled', false);
                    $("#runAct").html('<i class="fa fa-play"></i> {{ lang._("Run Now") }}');
                    
                    // Show result
                    if (data && data.result) {
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_INFO,
                            title: '{{ lang._("Results") }}',
                            message: data.result.replace(/\n/g, '<br>'),
                            buttons: [{
                                label: '{{ lang._("Close") }}',
                                action: function(dialogRef) {
                                    dialogRef.close();
                                }
                            }]
                        });
                    }
                    
                    // Update stats and threats
                    updateStats();
                    updateThreats();
                }
            );
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
                    if (data && data.stats) {
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
                    var threats = data && data.threats ? data.threats : [];
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
                    if (data && data.logs) {
                        var logContentDiv = $("#log-content");
                        logContentDiv.empty();
                        
                        if (data.logs.length > 0) {
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

<div class="tab-content content-box">
    <div id="settings" class="tab-pane fade in active">
        <div class="content-box-main">
            <form id="frm_GeneralSettings">
                <div class="table-responsive">
                    <!-- Use standardized OPNsense form rendering -->
                    {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_GeneralSettings']) }}
                </div>
                
                <div class="col-md-12">
                    <hr/>
                    <button class="btn btn-primary" id="saveAct" type="button"><b>{{ lang._('Save') }}</b></button>
                    <button class="btn btn-info" id="runAct" type="button"><i class="fa fa-play"></i> <b>{{ lang._('Run Now') }}</b></button>
                </div>
            </form>
        </div>
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