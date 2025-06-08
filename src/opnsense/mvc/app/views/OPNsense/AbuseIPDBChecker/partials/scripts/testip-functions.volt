<script>
    // ================================
    // TEST IP FUNCTIONALITY MODULE
    // ================================

    // Helper function to classify threat level
    function classifyThreatLevel(abuseScore) {
        if (abuseScore < 40) return 0;
        else if (abuseScore < 70) return 1;
        else return 2;
    }

    // Test IP button handler  
    $("#testIpBtn").click(function() {
        var ip = $("#ipToTest").val().trim();
        
        // Input validation
        if (!ip) {
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_WARNING,
                title: "{{ lang._('Warning') }}",
                message: "{{ lang._('Please enter an IP address') }}"
            });
            return;
        }
        
        var ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        if (!ipRegex.test(ip)) {
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_DANGER,
                title: "{{ lang._('Error') }}",
                message: "{{ lang._('Invalid IP address format') }}"
            });
            return;
        }
        
        // Start testing process
        $("#testIpBtn").prop("disabled", true);
        $("#testResultAlert").removeClass("hidden alert-success alert-danger alert-warning")
            .addClass("alert-info")
            .text("{{ lang._('Testing IP address...') }}");
        $("#testResults").removeClass("hidden");
        $("#testResultTable").addClass("hidden");
        
        // Execute API call
        $.ajax({
            url: "/api/abuseipdbchecker/service/testip",
            type: "POST",
            data: JSON.stringify({"ip": ip}),
            contentType: "application/json",
            dataType: "json",
            timeout: 30000,
            success: function(data, status) {
                handleTestIpSuccess(data);
            },
            error: function(xhr, status, error) {
                handleTestIpError(xhr);
            }
        });
    });

    // Handle successful test IP response
    function handleTestIpSuccess(data) {
        $("#testIpBtn").prop("disabled", false);
        
        if (data && data.status === 'ok') {
            var threatLevel = data.threat_level !== undefined ? data.threat_level : classifyThreatLevel(data.abuse_score);
            var alertClass = determineAlertClass(threatLevel, data.abuse_score);
            var alertText = generateAlertText(threatLevel, data.abuse_score);
            
            // Update alert display
            $("#testResultAlert").removeClass("alert-info alert-danger alert-warning alert-success")
                .addClass(alertClass)
                .text(alertText);
            
            // Populate result table
            populateTestResults(data, threatLevel);
            
            // Show results table
            $("#testResultTable").removeClass("hidden");
            
            // Refresh all related data
            refreshAllData();
        } else {
            showTestError(data.message || "{{ lang._('Error testing IP address') }}");
        }
    }

    // Handle test IP error response
    function handleTestIpError(xhr) {
        $("#testIpBtn").prop("disabled", false);
        
        var errorMsg = "{{ lang._('Error communicating with server') }}";
        if (xhr.status) {
            errorMsg += " (HTTP " + xhr.status + ")";
        }
        
        showTestError(errorMsg);
    }

    // Determine alert class based on threat level
    function determineAlertClass(threatLevel, abuseScore) {
        if (threatLevel === 2) {
            return "alert-danger";
        } else if (threatLevel === 1) {
            return "alert-warning";
        } else {
            return "alert-success";
        }
    }

    // Generate alert text based on threat level
    function generateAlertText(threatLevel, abuseScore) {
        if (threatLevel === 2) {
            return "{{ lang._('Malicious IP detected with score ') }}" + abuseScore + "%";
        } else if (threatLevel === 1) {
            return "{{ lang._('Suspicious IP detected with score ') }}" + abuseScore + "%";
        } else {
            return "{{ lang._('IP appears to be safe with score ') }}" + abuseScore + "%";
        }
    }

    // Populate test results table
    function populateTestResults(data, threatLevel) {
        $("#result-ip").text(data.ip);
        $("#result-threat").html(getThreatStatusBadge(threatLevel, data.abuse_score));
        $("#result-score").text(data.abuse_score + "%");
        $("#result-country").html(getCountryDisplay(data.country));
        $("#result-isp").text(data.isp);
        $("#result-domain").text(data.domain);
        $("#result-reports").text(data.reports);
        $("#result-last-reported").text(data.last_reported);
        $("#result-abusedb-link").html(
            '<a href="https://www.abuseipdb.com/check/' + data.ip + 
            '" target="_blank" class="btn btn-xs btn-primary">' +
            '<i class="fa fa-external-link"></i> {{ lang._("View Full Report") }}</a>'
        );
    }

    // Show test error message
    function showTestError(message) {
        $("#testResultAlert").removeClass("alert-info alert-success alert-warning")
            .addClass("alert-danger")
            .text(message);
        $("#testResultTable").addClass("hidden");
    }

    // Refresh all data after test
    function refreshAllData() {
        updateStats();
        updateThreats();
        updateAllScannedIPs();
        updateLogs();
        updateExternalIPs();
    }
</script>