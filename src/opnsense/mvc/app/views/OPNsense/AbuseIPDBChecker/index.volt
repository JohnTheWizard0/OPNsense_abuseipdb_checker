<script>
    $(document).ready(function() {
        
        // Helper function to get country flag and name using CSS flag icons
        function getCountryDisplay(countryCode) {
            if (!countryCode || countryCode === 'Unknown' || countryCode === '' || countryCode === null) {
                return 'Unknown';
            }
            
            var code = String(countryCode).toLowerCase().trim();
            var countryNames = {
                'ad': 'Andorra', 'ae': 'United Arab Emirates', 'af': 'Afghanistan', 'ag': 'Antigua and Barbuda',
                'ai': 'Anguilla', 'al': 'Albania', 'am': 'Armenia', 'ao': 'Angola', 'ar': 'Argentina',
                'at': 'Austria', 'au': 'Australia', 'az': 'Azerbaijan', 'ba': 'Bosnia and Herzegovina',
                'bb': 'Barbados', 'bd': 'Bangladesh', 'be': 'Belgium', 'bg': 'Bulgaria', 'bh': 'Bahrain',
                'bo': 'Bolivia', 'br': 'Brazil', 'bs': 'Bahamas', 'bw': 'Botswana', 'by': 'Belarus',
                'bz': 'Belize', 'ca': 'Canada', 'ch': 'Switzerland', 'cl': 'Chile', 'cn': 'China',
                'co': 'Colombia', 'cr': 'Costa Rica', 'cu': 'Cuba', 'cy': 'Cyprus', 'cz': 'Czechia',
                'de': 'Germany', 'dk': 'Denmark', 'do': 'Dominican Republic', 'dz': 'Algeria',
                'ec': 'Ecuador', 'ee': 'Estonia', 'eg': 'Egypt', 'es': 'Spain', 'et': 'Ethiopia',
                'fi': 'Finland', 'fj': 'Fiji', 'fr': 'France', 'gb': 'United Kingdom', 'ge': 'Georgia',
                'gh': 'Ghana', 'gr': 'Greece', 'gt': 'Guatemala', 'hk': 'Hong Kong', 'hn': 'Honduras',
                'hr': 'Croatia', 'ht': 'Haiti', 'hu': 'Hungary', 'id': 'Indonesia', 'ie': 'Ireland',
                'il': 'Israel', 'in': 'India', 'iq': 'Iraq', 'ir': 'Iran', 'is': 'Iceland',
                'it': 'Italy', 'jm': 'Jamaica', 'jo': 'Jordan', 'jp': 'Japan', 'ke': 'Kenya',
                'kg': 'Kyrgyzstan', 'kh': 'Cambodia', 'kp': 'North Korea', 'kr': 'South Korea',
                'kw': 'Kuwait', 'kz': 'Kazakhstan', 'la': 'Laos', 'lb': 'Lebanon', 'li': 'Liechtenstein',
                'lk': 'Sri Lanka', 'lt': 'Lithuania', 'lu': 'Luxembourg', 'lv': 'Latvia', 'ly': 'Libya',
                'ma': 'Morocco', 'md': 'Moldova', 'me': 'Montenegro', 'mk': 'North Macedonia',
                'mm': 'Myanmar', 'mn': 'Mongolia', 'mo': 'Macao', 'mx': 'Mexico', 'my': 'Malaysia',
                'mz': 'Mozambique', 'na': 'Namibia', 'ng': 'Nigeria', 'ni': 'Nicaragua',
                'nl': 'Netherlands', 'no': 'Norway', 'np': 'Nepal', 'nz': 'New Zealand', 'om': 'Oman',
                'pa': 'Panama', 'pe': 'Peru', 'ph': 'Philippines', 'pk': 'Pakistan', 'pl': 'Poland',
                'pt': 'Portugal', 'py': 'Paraguay', 'qa': 'Qatar', 'ro': 'Romania', 'rs': 'Serbia',
                'ru': 'Russia', 'rw': 'Rwanda', 'sa': 'Saudi Arabia', 'sd': 'Sudan', 'se': 'Sweden',
                'sg': 'Singapore', 'si': 'Slovenia', 'sk': 'Slovakia', 'sn': 'Senegal', 'so': 'Somalia',
                'sy': 'Syria', 'th': 'Thailand', 'tj': 'Tajikistan', 'tn': 'Tunisia', 'tr': 'Turkey',
                'tw': 'Taiwan', 'tz': 'Tanzania', 'ua': 'Ukraine', 'ug': 'Uganda', 'us': 'United States',
                'uy': 'Uruguay', 'uz': 'Uzbekistan', 've': 'Venezuela', 'vn': 'Vietnam', 'ye': 'Yemen',
                'za': 'South Africa', 'zm': 'Zambia', 'zw': 'Zimbabwe'
            };
    
            var countryName = countryNames[code] || code.toUpperCase();
            var flagPath = '/abuseipdbchecker/assets/flags/' + code + '.svg';
            
            return '<img src="' + flagPath + '" class="country-flag-local" alt="' + code + '" onerror="this.style.display=\'none\';this.nextSibling.style.display=\'inline\'"> <span style="display:none" class="country-badge">' + code.toUpperCase() + '</span> ' + countryName;
        }
        // Helper function to get just the flag icon
        function getCountryFlag(countryCode) {
            if (!countryCode || countryCode === 'Unknown' || countryCode === '' || countryCode === null) {
                return '';
            }
            
            var code = String(countryCode).toLowerCase().trim();
            var flagPath = '/abuseipdbchecker/assets/flags/' + code + '.svg';
            
            return '<img src="' + flagPath + '" class="country-flag-local" alt="' + code + '" onerror="this.style.display=\'none\'">';
        }
        
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
            
            // Send the data to the server
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
            
            // Enhanced AJAX call with better error handling
            $.ajax({
                url: "/api/abuseipdbchecker/service/testip",
                type: "POST",
                data: JSON.stringify({"ip": ip}),
                contentType: "application/json",
                dataType: "json",
                timeout: 30000, // 30 second timeout
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
                        $("#result-country").html(getCountryDisplay(data.country));
                        $("#result-isp").text(data.isp);
                        $("#result-domain").text(data.domain);
                        $("#result-reports").text(data.reports);
                        $("#result-last-reported").text(data.last_reported);
                        $("#result-abusedb-link").html('<a href="https://www.abuseipdb.com/check/' + data.ip + 
                        '" target="_blank" class="btn btn-xs btn-primary"><i class="fa fa-external-link"></i> {{ lang._("View Full Report") }}</a>');
                                                
                        $("#testResultTable").removeClass("hidden");
                        
                        // Refresh stats after test
                        updateStats();
                        updateThreats();
                        updateLogs();

                        // AUTO-REFRESH External IPs tab to show updated status immediately
                        updateExternalIPs();
                        
                        // Show visual feedback that external IPs were updated
                        setTimeout(function() {
                            if ($("#external-ips-info").is(":visible")) {
                                $("#external-ips-info").removeClass("alert-success alert-warning alert-danger")
                                    .addClass("alert-info")
                                    .text("{{ lang._('External IPs updated - IP ') }}" + data.ip + "{{ lang._(' status refreshed') }}")
                                    .fadeIn().delay(3000).fadeOut();
                            }
                        }, 500);

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
                    
                    // Enhanced error messaging
                    var errorMsg = "{{ lang._('Error communicating with server') }}";
                    if (xhr.status) {
                        errorMsg += " (HTTP " + xhr.status + ")";
                    }
                    if (xhr.responseText) {
                        try {
                            var errorData = JSON.parse(xhr.responseText);
                            if (errorData.message) {
                                errorMsg = errorData.message;
                            }
                        } catch(e) {
                            // If response isn't JSON, show first 100 chars
                            errorMsg += ": " + xhr.responseText.substring(0, 100);
                        }
                    }
                    
                    console.error("AJAX Error:", {
                        status: xhr.status,
                        statusText: xhr.statusText,
                        responseText: xhr.responseText,
                        error: error
                    });
                    
                    $("#testResultAlert").removeClass("alert-info alert-success alert-warning")
                        .addClass("alert-danger")
                        .text(errorMsg);
                    $("#testResultTable").addClass("hidden");
                }
            });
        });
        
        function updateExternalIPs() {
            $("#external-ips-info").show().text("{{ lang._('Loading external IPs...') }}");
            $("#external-ips-table").empty();
            
            ajaxCall("/api/abuseipdbchecker/service/listips", {}, function(data) {
                $("#external-ips-info").hide();
                
                if (data && data.status === 'ok' && data.ips) {
                    var ipTable = $("#external-ips-table");
                    ipTable.empty();
                    
                    if (data.ips.length === 0) {
                        ipTable.append('<tr><td colspan="5">{{ lang._("No external IPs found in firewall logs") }}</td></tr>');
                    } else {
                        $("#external-ips-info").removeClass("alert-info alert-danger")
                            .addClass("alert-success")
                            .text("{{ lang._('Found ') }}" + data.total_count + "{{ lang._(' external IPs') }}")
                            .show();
                        
                        $.each(data.ips, function(i, ipData) {
                            var row = $('<tr>');
                            row.append($('<td>').text(ipData.ip));
                            row.append($('<td>').text(ipData.checked));
                            
                            var statusCell = $('<td>');
                            if (ipData.threat_status === 'Threat') {
                                statusCell.html('<span class="label label-danger">{{ lang._("Threat") }}</span>');
                            } else if (ipData.threat_status === 'Safe') {
                                statusCell.html('<span class="label label-success">{{ lang._("Safe") }}</span>');
                            } else {
                                statusCell.html('<span class="label label-default">{{ lang._("Unknown") }}</span>');
                            }
                            row.append(statusCell);
                            
                            row.append($('<td>').text(ipData.last_checked));
                            
                            var actionsCell = $('<td>');
                            actionsCell.html('<button class="btn btn-xs btn-primary test-ip-btn" data-ip="' + ipData.ip + '">{{ lang._("Test Now") }}</button>');
                            row.append(actionsCell);
                            
                            ipTable.append(row);
                        });
                        
                        // Add click handlers for test buttons
                        $('.test-ip-btn').click(function() {
                            var ip = $(this).data('ip');
                            $("#ipToTest").val(ip);
                            $('a[href="#testip"]').tab('show');
                            $("#testIpBtn").click();
                        });
                    }
                } else if (data && data.status === 'disabled') {
                    $("#external-ips-info").removeClass("alert-info alert-success")
                        .addClass("alert-warning")
                        .text("{{ lang._('AbuseIPDBChecker is disabled. Enable it in General settings to see external IPs.') }}")
                        .show();
                    $("#external-ips-table").append('<tr><td colspan="5">{{ lang._("Service is disabled") }}</td></tr>');
                } else {
                    $("#external-ips-info").removeClass("alert-info alert-success")
                        .addClass("alert-danger")
                        .text(data.message || "{{ lang._('Error retrieving external IPs') }}")
                        .show();
                    $("#external-ips-table").append('<tr><td colspan="5">{{ lang._("Error loading external IPs") }}</td></tr>');
                }
            });
        }

       // Functions to update the dashboard data - with error handling
        function updateStats() {
            ajaxCall("/api/abuseipdbchecker/service/stats", {}, function(data) {
                if (data && data.status === 'ok') {
                    $("#total-ips-checked").text(data.total_ips || 0);
                    $("#total-threats").text(data.total_threats || 0);
                    $("#checks-today").text(data.daily_checks || 0);
                    $("#last-run").text(data.last_check || 'Never');
                }
            }, function() {
                // Handle errors silently for background updates
                console.log('Stats update failed');
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
                            row.append($('<td>').html(getCountryDisplay(threat.country)));
                            row.append($('<td>').html('<a href="https://www.abuseipdb.com/check/' + threat.ip + '" target="_blank">{{ lang._("View") }}</a>'));
                            threatTable.append(row);
                        });
                    }
                }
            }, function() {
                console.log('Threats update failed');
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
            }, function() {
                console.log('Logs update failed');
            });
        }

        // Optimized service status refresh - only when page is visible
        function refreshServiceStatus() {
            // Skip if page is not visible
            if (document.hidden) {
                return;
            }
            
            $.ajax({
                url: '/api/abuseipdbchecker/service/status',
                type: 'POST',
                dataType: 'json',
                timeout: 5000,
                success: function(data) {
                    if (data && data.status === 'running') {
                        $('.service-abuseipdbchecker .service-status').removeClass('text-danger').addClass('text-success').text('Running');
                        $('.service-abuseipdbchecker .btn-start').prop('disabled', true);
                        $('.service-abuseipdbchecker .btn-stop').prop('disabled', false);
                    } else {
                        $('.service-abuseipdbchecker .service-status').removeClass('text-success').addClass('text-danger').text('Stopped');
                        $('.service-abuseipdbchecker .btn-start').prop('disabled', false);
                        $('.service-abuseipdbchecker .btn-stop').prop('disabled', true);
                    }
                },
                error: function() {
                    // Silently handle errors to prevent console spam
                    console.log('Service status check failed - daemon may be starting');
                }
            });
        }

        // Reduced polling frequency and better lifecycle management
        var statusInterval = setInterval(refreshServiceStatus, 10000); // Every 10 seconds instead of 3

        // Pause polling when page is hidden
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                clearInterval(statusInterval);
            } else {
                statusInterval = setInterval(refreshServiceStatus, 10000);
                refreshServiceStatus(); // Immediate check when page becomes visible
            }
        });

        // Initial call
        refreshServiceStatus();
        
        // Refresh buttons
        $("#refreshStats").click(updateStats);
        $("#refreshExternalIPs").click(updateExternalIPs);
        $("#refreshThreats").click(updateThreats);
        $("#refreshLogs").click(updateLogs);

        // Tab update throttling
        var lastTabUpdate = {};
        
        // Add tab change event handlers - with throttling
        $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            var target = $(e.target).attr("href");
            var now = Date.now();
            
            // Throttle updates to prevent spam
            if (lastTabUpdate[target] && (now - lastTabUpdate[target]) < 5000) {
                return; // Skip if updated less than 5 seconds ago
            }
            
            lastTabUpdate[target] = now;
            
            if (target === "#stats") {
                updateStats();
            } else if (target === "#externalips") {
                updateExternalIPs();
            } else if (target === "#threats") {
                updateThreats();
            } else if (target === "#logs") {
                updateLogs();
            }
        });
        

        
        // Initial data load
        updateStats();
        updateExternalIPs();
        updateThreats();
        updateLogs();
    });
</script>

<style>
    .country-flag-icon {
        display: inline-block;
        width: 1.33em;
        height: 1em;
        margin-right: 0.5em;
        vertical-align: text-bottom;
    }

    .country-flag-local {
        width: 20px;
        height: 15px;
        margin-right: 0.5em;
        vertical-align: middle;
        border: 1px solid #ccc;
        border-radius: 2px;
    }
    
    /* Ensure consistent flag sizing in tables */
    .table .country-flag-icon {
        width: 1.2em;
        height: 0.9em;
    }
    
    /* Better flag rendering */
    .fi {
        border-radius: 2px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }
</style>
    

<!-- Main Settings Tabs -->
<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#network">{{ lang._('Network') }}</a></li>
    <li><a data-toggle="tab" href="#api">{{ lang._('API') }}</a></li>
    <li><a data-toggle="tab" href="#email">{{ lang._('Email') }}</a></li>
    <li><a data-toggle="tab" href="#testip">{{ lang._('Test IP') }}</a></li>
</ul>

<div class="tab-content content-box">
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
    
    <!-- Save Button -->
    <div class="col-md-12">
        <button class="btn btn-primary" id="saveAct" type="button">
            <b>{{ lang._('Save') }}</b> <i id="saveAct_progress" class=""></i>
        </button>
    </div>
</div>

<!-- Statistics & Monitoring Section -->
<div class="content-box" style="margin-top: 20px;">
    <ul class="nav nav-tabs" data-tabs="tabs" id="abuseipdb-tabs">
        <li class="active"><a data-toggle="tab" href="#stats">{{ lang._('Statistics') }}</a></li>
        <li><a data-toggle="tab" href="#externalips">{{ lang._('External IPs') }}</a></li>
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
    </div>
</div>