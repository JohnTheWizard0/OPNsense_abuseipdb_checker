<script>
    // ================================
    // GLOBAL NAMESPACE - CRITICAL FIX
    // ================================
    window.AbuseIPDB = {
        currentPages: {
            threats: 1,
            allscannedips: 1
        },
        currentSearch: {
            threats: '',
            allscannedips: ''
        }
    };

    $(document).ready(function() {
        // Initialize all modules
        updateStats();
        updateExternalIPs();
        updateThreats();
        updateAllScannedIPs();
        updateLogs();
        updateServiceStatus();
        
        // Set up periodic service status monitoring
        setInterval(updateServiceStatus, 15000);
        
        // Tab change handlers
        var lastTabUpdate = {};
        $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            var target = $(e.target).attr("href");
            var now = Date.now();
            
            if (lastTabUpdate[target] && (now - lastTabUpdate[target]) < 5000) {
                return;
            }
            
            lastTabUpdate[target] = now;
            
            if (target === "#stats") {
                updateStats();
            } else if (target === "#externalips") {
                updateExternalIPs();
            } else if (target === "#allscannedips") {
                updateAllScannedIPs();
            } else if (target === "#threats") {
                updateThreats();
            } else if (target === "#logs") {
                updateLogs();
            }
        });
        
        // Enhanced refresh button handlers
        $("#refreshStats").click(updateStats);
        $("#refreshExternalIPs").click(updateExternalIPs);
        $("#refreshLogs").click(updateLogs);
        
        $("#refreshThreats").click(function() {
            window.AbuseIPDB.currentPages.threats = 1;
            window.AbuseIPDB.currentSearch.threats = '';
            $('#threats-search').val('');
            updateThreats();
        });
        
        $("#refreshAllScannedIPs").click(function() {
            window.AbuseIPDB.currentPages.allscannedips = 1;
            window.AbuseIPDB.currentSearch.allscannedips = '';
            $('#allips-search').val('');
            updateAllScannedIPs();
        });
        
        // Search functionality
        $('#threats-search').on('keyup', function() {
            var searchTerm = $(this).val().trim();
            window.AbuseIPDB.currentPages.threats = 1;
            updateThreats(1, searchTerm);
        });
        
        $('#allips-search').on('keyup', function() {
            var searchTerm = $(this).val().trim();
            window.AbuseIPDB.currentPages.allscannedips = 1;
            updateAllScannedIPs(1, searchTerm);
        });
    });
</script>

<!-- Include individual script modules -->
{{ partial("OPNsense/AbuseIPDBChecker/partials/scripts/update-functions") }}
{{ partial("OPNsense/AbuseIPDBChecker/partials/scripts/service-functions") }}
{{ partial("OPNsense/AbuseIPDBChecker/partials/scripts/config-functions") }}
{{ partial("OPNsense/AbuseIPDBChecker/partials/scripts/testip-functions") }}