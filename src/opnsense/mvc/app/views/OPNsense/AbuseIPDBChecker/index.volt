<script>
    $(document).ready(function() {
        
        // Load initial data
        var data_get_map = {
            'frm_general': "/api/abuseipdbchecker/settings/get",
            'frm_network': "/api/abuseipdbchecker/settings/get",
            'frm_api': "/api/abuseipdbchecker/settings/get",
            'frm_email': "/api/abuseipdbchecker/settings/get"
        };
        mapDataToFormUI(data_get_map).done(function() {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            // Update statistics after form load
            updateStats();
        });

        // Save button handler
        $("#saveAct").click(function() {

            console.log("Save button clicked");
    
            // Show saving indicator
            $("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
            
            // Build a complete data object from all forms
            var data = {
                'abuseipdbchecker': {}
            };
            
            // Extract data from each form and merge into one object
            ["general", "network", "api", "email"].forEach(function(section) {
                var formData = getFormData("frm_" + section);
                
                // The key here is to ensure we're getting the right structure
                if (formData && formData.abuseipdbchecker && formData.abuseipdbchecker[section]) {
                    data.abuseipdbchecker[section] = formData.abuseipdbchecker[section];
                }
            });

            // Validate API key if enabled
            var enabled = $("#abuseipdbchecker\\.general\\.Enabled").prop('checked');
            var apiKey = $("#abuseipdbchecker\\.api\\.Key").val();
            
            if (enabled && (apiKey === "" || apiKey === "YOUR_API_KEY")) {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: "{{ lang._('Error') }}",
                    message: "{{ lang._('API key is required to enable the plugin. Please configure a valid API key in the API tab.') }}",
                    buttons: [{
                        label: "{{ lang._('Close') }}",
                        action: function(dialogRef) {
                            dialogRef.close();
                        }
                    }]
                });
                return;
            }
            
            // Now send the combined data
            // Send the data to the server
            // Send a single API call with the complete data
            ajaxCall(
                "/api/abuseipdbchecker/settings/set",
                data,
                function(data, status) {
                    // Hide the spinner
                    $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                    
                    if (data.result === "saved") {
                        // Success notification
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_SUCCESS,
                            title: "{{ lang._('Settings saved') }}",
                            message: "{{ lang._('All settings have been saved successfully.') }}"
                        });
                        
                        // Refresh data displays
                        updateStats();
                        updateThreats();
                        updateLogs();
                    } else {
                        // Error notification
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_DANGER,
                            title: "{{ lang._('Error') }}",
                            message: "{{ lang._('There was an error saving settings.') }}"
                        });
                    }
                }
            );

        });
        
        // Test IP button handler
        $("#testIpBtn").click(function() {
            var ip = $("#ipToTest").val().trim();
            if (!ip) {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_WARNING,
                    title: "{{ lang._('Warning') }}",
                    message: "{{ lang._('Please enter an IP address') }}"
                });
                return;
            }
            
            // Validate IP format
            var ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
            if (!ipRegex.test(ip)) {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: "{{ lang._('Error') }}",
                    message: "{{ lang._('Invalid IP address format') }}"
                });
                return;
            }
            
            // Show loading indicator
            $("#testIpBtn").prop("disabled", true);
            $("#testResultAlert").removeClass("hidden alert-success alert-danger alert-warning")
                .addClass("alert-info")
                .text("{{ lang._('Testing IP address...') }}");
            $("#testResults").removeClass("hidden");
            $("#testResultTable").addClass("hidden");
            
            // Call API
            // Replace the ajaxCall section with:
            $.ajax({
                url: "/api/abuseipdbchecker/service/testip",
                type: "POST",
                data: JSON.stringify({"ip": ip}),
                contentType: "application/json",
                dataType: "json",
                success: function(data, status) {
                    $("#testIpBtn").prop("disabled", false);
                    
                    if (data && data.status === 'ok') {
                        // Show results
                        $("#testResultAlert").removeClass("alert-info alert-danger alert-warning")
                            .addClass(data.is_threat ? "alert-danger" : "alert-success")
                            .text(data.is_threat ? 
                                "{{ lang._('Malicious IP detected with score ') }}" + data.abuse_score + "%" : 
                                "{{ lang._('IP appears to be safe with score ') }}" + data.abuse_score + "%");
                        
                        // Fill in the table
                        $("#result-ip").text(data.ip);
                        $("#result-threat").html(data.is_threat ? 
                            '<span class="label label-danger">{{ lang._("Malicious") }}</span>' : 
                            '<span class="label label-success">{{ lang._("Safe") }}</span>');
                        $("#result-score").text(data.abuse_score + "%");
                        $("#result-country").text(data.country);
                        $("#result-isp").text(data.isp);
                        $("#result-domain").text(data.domain);
                        $("#result-reports").text(data.reports);
                        $("#result-last-reported").text(data.last_reported);
                        
                        $("#testResultTable").removeClass("hidden");
                        
                        // Refresh stats after test
                        updateStats();
                        updateThreats();
                        updateLogs();
                    } else {
                        // Show error
                        $("#testResultAlert").removeClass("alert-info alert-success alert-warning")
                            .addClass("alert-danger")
                            .text(data.message || "{{ lang._('Error testing IP address') }}");
                        $("#testResultTable").addClass("hidden");
                    }
                },
                error: function(xhr, status, error) {
                    $("#testIpBtn").prop("disabled", false);
                    $("#testResultAlert").removeClass("alert-info alert-success alert-warning")
                        .addClass("alert-danger")
                        .text("{{ lang._('Error communicating with server') }}");
                    $("#testResultTable").addClass("hidden");
                }
            });
        });
        
        // Functions to update the dashboard data
        function updateStats() {
            ajaxCall("/api/abuseipdbchecker/service/stats", {}, function(data) {
                if (data && data.status === 'ok') {
                    $("#total-ips-checked").text(data.total_ips || 0);
                    $("#total-threats").text(data.total_threats || 0);
                    $("#checks-today").text(data.daily_checks || 0);
                    $("#last-run").text(data.last_check || 'Never');
                }
            });
        }
        
        function updateThreats() {
            ajaxCall("/api/abuseipdbchecker/service/threats", {}, function(data) {
                if (data && data.status === 'ok' && data.threats) {
                    var threatTable = $("#recent-threats-table");
                    threatTable.empty();
                    
                    if (data.threats.length === 0) {
                        threatTable.append('<tr><td colspan="5">{{ lang._("No threats detected") }}</td></tr>');
                    } else {
                        $.each(data.threats, function(i, threat) {
                            var row = $('<tr>');
                            row.append($('<td>').text(threat.ip));
                            row.append($('<td>').text(threat.score + '%'));
                            row.append($('<td>').text(threat.last_seen));
                            row.append($('<td>').text(threat.country));
                            row.append($('<td>').html('<a href="https://www.abuseipdb.com/check/' + threat.ip + '" target="_blank">{{ lang._("View") }}</a>'));
                            threatTable.append(row);
                        });
                    }
                }
            });
        }
        
        function updateLogs() {
            ajaxCall("/api/abuseipdbchecker/service/logs", {}, function(data) {
                if (data && data.status === 'ok' && data.logs) {
                    var logContent = "";
                    if (data.logs.length === 0) {
                        logContent = "{{ lang._('No log entries found.') }}";
                    } else {
                        logContent = data.logs.join('\n');
                    }
                    $("#log-content").text(logContent);
                } else {
                    $("#log-content").text(data.message || "{{ lang._('Error retrieving logs.') }}");
                }
            });
        }
        
        // Add tab change event handlers
        $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            var target = $(e.target).attr("href");
            if (target === "#stats") {
                updateStats();
            } else if (target === "#threats") {
                updateThreats();
            } else if (target === "#logs") {
                updateLogs();
            }
        });
        
        // Refresh buttons
        $("#refreshStats").click(updateStats);
        $("#refreshThreats").click(updateThreats);
        $("#refreshLogs").click(updateLogs);
        
        // Initial data load
        updateStats();
        updateThreats();
        updateLogs();
    });
</script>

<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#stats">{{ lang._('Statistics') }}</a></li>
    <li><a data-toggle="tab" href="#threats">{{ lang._('Recent Threats') }}</a></li>
    <li><a data-toggle="tab" href="#logs">{{ lang._('Logs') }}</a></li>
    <li><a data-toggle="tab" href="#test">{{ lang._('Test IP') }}</a></li>
</ul>

<div class="tab-content content-box">
    <!-- Settings Tab -->
    <div id="settings" class="tab-pane fade in active">
        <div class="content-box" style="padding-bottom: 1.5em;">
            <ul class="nav nav-tabs" role="tablist">
                <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
                <li><a data-toggle="tab" href="#network">{{ lang._('Network') }}</a></li>
                <li><a data-toggle="tab" href="#api">{{ lang._('API') }}</a></li>
                <li><a data-toggle="tab" href="#email">{{ lang._('Email') }}</a></li>
            </ul>
            
            <div class="tab-content">
                <!-- General Settings -->
                <div id="general" class="tab-pane fade in active">
                    <div class="content-box">
                        {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_general','parent':'abuseipdbchecker']) }}
                    </div>
                </div>
                
                <!-- Network Settings -->
                <div id="network" class="tab-pane fade">
                    <div class="content-box">
                        {{ partial("layout_partials/base_form",['fields':networkForm,'id':'frm_network','parent':'abuseipdbchecker']) }}
                    </div>
                </div>
                
                <!-- API Settings -->
                <div id="api" class="tab-pane fade">
                    <div class="content-box">
                        {{ partial("layout_partials/base_form",['fields':apiForm,'id':'frm_api','parent':'abuseipdbchecker']) }}
                    </div>
                </div>
                
                <!-- Email Settings -->
                <div id="email" class="tab-pane fade">
                    <div class="content-box">
                        {{ partial("layout_partials/base_form",['fields':emailForm,'id':'frm_email','parent':'abuseipdbchecker']) }}
                    </div>
                </div>
            </div>
            
            <div class="col-md-12">
                <button class="btn btn-primary" id="saveAct" type="button">
                    <b>{{ lang._('Save') }}</b> <i id="saveAct_progress" class=""></i>
                </button>
            </div>
        </div>
    </div>
    
    <!-- Statistics Tab -->
    <div id="stats" class="tab-pane fade">
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
            </div>
        </div>
    </div>
    
    <!-- Recent Threats Tab -->
    <div id="threats" class="tab-pane fade">
        <div class="container-fluid">
            <div class="row">
                <div class="col-md-12">
                    <button id="refreshThreats" class="btn btn-xs btn-primary pull-right">
                        <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                    </button>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
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
    
    <!-- Test IP Tab -->
    <div id="test" class="tab-pane fade">
        <div class="container-fluid">
            <div class="row">
                <div class="col-md-12">
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
        </div>
    </div>
</div>