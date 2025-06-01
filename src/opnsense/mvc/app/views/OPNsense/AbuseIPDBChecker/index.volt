<script>
    $(document).ready(function() {
        
         // Country flags data - embedded for reliability
         var countryFlags = {
            "AD": {"name": "Andorra", "flag": "🇦🇩"},
            "AE": {"name": "United Arab Emirates", "flag": "🇦🇪"},
            "AF": {"name": "Afghanistan", "flag": "🇦🇫"},
            "AG": {"name": "Antigua and Barbuda", "flag": "🇦🇬"},
            "AI": {"name": "Anguilla", "flag": "🇦🇮"},
            "AL": {"name": "Albania", "flag": "🇦🇱"},
            "AM": {"name": "Armenia", "flag": "🇦🇲"},
            "AO": {"name": "Angola", "flag": "🇦🇴"},
            "AR": {"name": "Argentina", "flag": "🇦🇷"},
            "AT": {"name": "Austria", "flag": "🇦🇹"},
            "AU": {"name": "Australia", "flag": "🇦🇺"},
            "AZ": {"name": "Azerbaijan", "flag": "🇦🇿"},
            "BA": {"name": "Bosnia and Herzegovina", "flag": "🇧🇦"},
            "BB": {"name": "Barbados", "flag": "🇧🇧"},
            "BD": {"name": "Bangladesh", "flag": "🇧🇩"},
            "BE": {"name": "Belgium", "flag": "🇧🇪"},
            "BG": {"name": "Bulgaria", "flag": "🇧🇬"},
            "BH": {"name": "Bahrain", "flag": "🇧🇭"},
            "BO": {"name": "Bolivia", "flag": "🇧🇴"},
            "BR": {"name": "Brazil", "flag": "🇧🇷"},
            "BS": {"name": "Bahamas", "flag": "🇧🇸"},
            "BW": {"name": "Botswana", "flag": "🇧🇼"},
            "BY": {"name": "Belarus", "flag": "🇧🇾"},
            "BZ": {"name": "Belize", "flag": "🇧🇿"},
            "CA": {"name": "Canada", "flag": "🇨🇦"},
            "CH": {"name": "Switzerland", "flag": "🇨🇭"},
            "CL": {"name": "Chile", "flag": "🇨🇱"},
            "CN": {"name": "China", "flag": "🇨🇳"},
            "CO": {"name": "Colombia", "flag": "🇨🇴"},
            "CR": {"name": "Costa Rica", "flag": "🇨🇷"},
            "CU": {"name": "Cuba", "flag": "🇨🇺"},
            "CY": {"name": "Cyprus", "flag": "🇨🇾"},
            "CZ": {"name": "Czechia", "flag": "🇨🇿"},
            "DE": {"name": "Germany", "flag": "🇩🇪"},
            "DK": {"name": "Denmark", "flag": "🇩🇰"},
            "DO": {"name": "Dominican Republic", "flag": "🇩🇴"},
            "DZ": {"name": "Algeria", "flag": "🇩🇿"},
            "EC": {"name": "Ecuador", "flag": "🇪🇨"},
            "EE": {"name": "Estonia", "flag": "🇪🇪"},
            "EG": {"name": "Egypt", "flag": "🇪🇬"},
            "ES": {"name": "Spain", "flag": "🇪🇸"},
            "ET": {"name": "Ethiopia", "flag": "🇪🇹"},
            "FI": {"name": "Finland", "flag": "🇫🇮"},
            "FJ": {"name": "Fiji", "flag": "🇫🇯"},
            "FR": {"name": "France", "flag": "🇫🇷"},
            "GB": {"name": "United Kingdom", "flag": "🇬🇧"},
            "GE": {"name": "Georgia", "flag": "🇬🇪"},
            "GH": {"name": "Ghana", "flag": "🇬🇭"},
            "GR": {"name": "Greece", "flag": "🇬🇷"},
            "GT": {"name": "Guatemala", "flag": "🇬🇹"},
            "HK": {"name": "Hong Kong", "flag": "🇭🇰"},
            "HN": {"name": "Honduras", "flag": "🇭🇳"},
            "HR": {"name": "Croatia", "flag": "🇭🇷"},
            "HT": {"name": "Haiti", "flag": "🇭🇹"},
            "HU": {"name": "Hungary", "flag": "🇭🇺"},
            "ID": {"name": "Indonesia", "flag": "🇮🇩"},
            "IE": {"name": "Ireland", "flag": "🇮🇪"},
            "IL": {"name": "Israel", "flag": "🇮🇱"},
            "IN": {"name": "India", "flag": "🇮🇳"},
            "IQ": {"name": "Iraq", "flag": "🇮🇶"},
            "IR": {"name": "Iran", "flag": "🇮🇷"},
            "IS": {"name": "Iceland", "flag": "🇮🇸"},
            "IT": {"name": "Italy", "flag": "🇮🇹"},
            "JM": {"name": "Jamaica", "flag": "🇯🇲"},
            "JO": {"name": "Jordan", "flag": "🇯🇴"},
            "JP": {"name": "Japan", "flag": "🇯🇵"},
            "KE": {"name": "Kenya", "flag": "🇰🇪"},
            "KG": {"name": "Kyrgyzstan", "flag": "🇰🇬"},
            "KH": {"name": "Cambodia", "flag": "🇰🇭"},
            "KP": {"name": "North Korea", "flag": "🇰🇵"},
            "KR": {"name": "South Korea", "flag": "🇰🇷"},
            "KW": {"name": "Kuwait", "flag": "🇰🇼"},
            "KZ": {"name": "Kazakhstan", "flag": "🇰🇿"},
            "LA": {"name": "Laos", "flag": "🇱🇦"},
            "LB": {"name": "Lebanon", "flag": "🇱🇧"},
            "LI": {"name": "Liechtenstein", "flag": "🇱🇮"},
            "LK": {"name": "Sri Lanka", "flag": "🇱🇰"},
            "LT": {"name": "Lithuania", "flag": "🇱🇹"},
            "LU": {"name": "Luxembourg", "flag": "🇱🇺"},
            "LV": {"name": "Latvia", "flag": "🇱🇻"},
            "LY": {"name": "Libya", "flag": "🇱🇾"},
            "MA": {"name": "Morocco", "flag": "🇲🇦"},
            "MD": {"name": "Moldova", "flag": "🇲🇩"},
            "ME": {"name": "Montenegro", "flag": "🇲🇪"},
            "MK": {"name": "North Macedonia", "flag": "🇲🇰"},
            "MM": {"name": "Myanmar", "flag": "🇲🇲"},
            "MN": {"name": "Mongolia", "flag": "🇲🇳"},
            "MO": {"name": "Macao", "flag": "🇲🇴"},
            "MX": {"name": "Mexico", "flag": "🇲🇽"},
            "MY": {"name": "Malaysia", "flag": "🇲🇾"},
            "MZ": {"name": "Mozambique", "flag": "🇲🇿"},
            "NA": {"name": "Namibia", "flag": "🇳🇦"},
            "NG": {"name": "Nigeria", "flag": "🇳🇬"},
            "NI": {"name": "Nicaragua", "flag": "🇳🇮"},
            "NL": {"name": "Netherlands", "flag": "🇳🇱"},
            "NO": {"name": "Norway", "flag": "🇳🇴"},
            "NP": {"name": "Nepal", "flag": "🇳🇵"},
            "NZ": {"name": "New Zealand", "flag": "🇳🇿"},
            "OM": {"name": "Oman", "flag": "🇴🇲"},
            "PA": {"name": "Panama", "flag": "🇵🇦"},
            "PE": {"name": "Peru", "flag": "🇵🇪"},
            "PH": {"name": "Philippines", "flag": "🇵🇭"},
            "PK": {"name": "Pakistan", "flag": "🇵🇰"},
            "PL": {"name": "Poland", "flag": "🇵🇱"},
            "PT": {"name": "Portugal", "flag": "🇵🇹"},
            "PY": {"name": "Paraguay", "flag": "🇵🇾"},
            "QA": {"name": "Qatar", "flag": "🇶🇦"},
            "RO": {"name": "Romania", "flag": "🇷🇴"},
            "RS": {"name": "Serbia", "flag": "🇷🇸"},
            "RU": {"name": "Russia", "flag": "🇷🇺"},
            "RW": {"name": "Rwanda", "flag": "🇷🇼"},
            "SA": {"name": "Saudi Arabia", "flag": "🇸🇦"},
            "SD": {"name": "Sudan", "flag": "🇸🇩"},
            "SE": {"name": "Sweden", "flag": "🇸🇪"},
            "SG": {"name": "Singapore", "flag": "🇸🇬"},
            "SI": {"name": "Slovenia", "flag": "🇸🇮"},
            "SK": {"name": "Slovakia", "flag": "🇸🇰"},
            "SN": {"name": "Senegal", "flag": "🇸🇳"},
            "SO": {"name": "Somalia", "flag": "🇸🇴"},
            "SY": {"name": "Syria", "flag": "🇸🇾"},
            "TH": {"name": "Thailand", "flag": "🇹🇭"},
            "TJ": {"name": "Tajikistan", "flag": "🇹🇯"},
            "TN": {"name": "Tunisia", "flag": "🇹🇳"},
            "TR": {"name": "Turkey", "flag": "🇹🇷"},
            "TW": {"name": "Taiwan", "flag": "🇹🇼"},
            "TZ": {"name": "Tanzania", "flag": "🇹🇿"},
            "UA": {"name": "Ukraine", "flag": "🇺🇦"},
            "UG": {"name": "Uganda", "flag": "🇺🇬"},
            "US": {"name": "United States", "flag": "🇺🇸"},
            "UY": {"name": "Uruguay", "flag": "🇺🇾"},
            "UZ": {"name": "Uzbekistan", "flag": "🇺🇿"},
            "VE": {"name": "Venezuela", "flag": "🇻🇪"},
            "VN": {"name": "Vietnam", "flag": "🇻🇳"},
            "YE": {"name": "Yemen", "flag": "🇾🇪"},
            "ZA": {"name": "South Africa", "flag": "🇿🇦"},
            "ZM": {"name": "Zambia", "flag": "🇿🇲"},
            "ZW": {"name": "Zimbabwe", "flag": "🇿🇼"}
        };

        // Helper function to get country flag and name
        function getCountryDisplay(countryCode) {
            if (!countryCode || countryCode === 'Unknown' || countryCode === '' || countryCode === null) {
                return 'Unknown';
            }
            
            var code = String(countryCode).toUpperCase().trim();
            var country = countryFlags[code];
            
            if (country && country.flag && country.name) {
                return '<span class="country-flag">' + country.flag + '</span> ' + country.name;
            }
            
            // Fallback: just return the country code
            return code;
        }

        // Helper function to get just the flag emoji
        function getCountryFlag(countryCode) {
            if (!countryCode || countryCode === 'Unknown' || countryCode === '' || countryCode === null) {
                return '';
            }
            
            var code = String(countryCode).toUpperCase().trim();
            var country = countryFlags[code];
            
            if (country && country.flag) {
                return country.flag;
            }
            
            return '';
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
                            row.append($('<td>').html(getCountryDisplay(threat.country)));
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

        // Force service status refresh every 3 seconds
        function refreshServiceStatus() {
            $.ajax({
                url: '/api/abuseipdbchecker/service/status',
                type: 'POST',
                dataType: 'json',
                success: function(data) {
                    if (data && data.status === 'running') {
                        // Force GUI to show running state
                        $('.service-abuseipdbchecker .service-status').removeClass('text-danger').addClass('text-success').text('Running');
                        $('.service-abuseipdbchecker .btn-start').prop('disabled', true);
                        $('.service-abuseipdbchecker .btn-stop').prop('disabled', false);
                    } else {
                        $('.service-abuseipdbchecker .service-status').removeClass('text-success').addClass('text-danger').text('Stopped');
                        $('.service-abuseipdbchecker .btn-start').prop('disabled', false);
                        $('.service-abuseipdbchecker .btn-stop').prop('disabled', true);
                    }
                }
            });
        }

        // Start polling
        setInterval(refreshServiceStatus, 3000);
        refreshServiceStatus(); // Initial call
        
        // Add tab change event handlers for bottom tabs
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


<style>
.country-flag {
    font-family: "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif;
    font-size: 1.2em;
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