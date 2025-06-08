<script>
    // ================================
    // SERVICE MANAGEMENT MODULE
    // ================================

    function updateServiceStatus() {
        $.ajax({
            url: '/api/abuseipdbchecker/service/status',
            type: 'POST',
            dataType: 'json',
            timeout: 5000,
            success: function(data) {
                if (data && data.status === 'running') {
                    $('#service-status').removeClass('text-danger text-warning').addClass('text-success').text('{{ lang._("Running") }}');
                    $('#service-start').prop('disabled', true);
                    $('#service-stop, #service-restart').prop('disabled', false);
                } else {
                    $('#service-status').removeClass('text-success text-warning').addClass('text-danger').text('{{ lang._("Stopped") }}');
                    $('#service-start').prop('disabled', false);
                    $('#service-stop, #service-restart').prop('disabled', true);
                }
            },
            error: function() {
                $('#service-status').removeClass('text-success text-danger').addClass('text-warning').text('{{ lang._("Unknown") }}');
                $('#service-start, #service-stop, #service-restart').prop('disabled', false);
            }
        });
    }

    // Service Start Handler
    $('#service-start').click(function() {
        $(this).prop('disabled', true);
        $('#service-status').text('{{ lang._("Starting...") }}');
        
        $.post('/api/abuseipdbchecker/service/start', function(data) {
            if (data && data.status === 'ok') {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: '{{ lang._("Success") }}',
                    message: '{{ lang._("Service started successfully") }}'
                });
            } else {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: '{{ lang._("Error") }}',
                    message: data.message || '{{ lang._("Failed to start service") }}'
                });
            }
            setTimeout(updateServiceStatus, 2000);
        }).fail(function() {
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_DANGER,
                title: '{{ lang._("Error") }}',
                message: '{{ lang._("Failed to communicate with service") }}'
            });
            setTimeout(updateServiceStatus, 2000);
        });
    });

    // Service Stop Handler
    $('#service-stop').click(function() {
        $(this).prop('disabled', true);
        $('#service-status').text('{{ lang._("Stopping...") }}');
        
        $.post('/api/abuseipdbchecker/service/stop', function(data) {
            if (data && data.status === 'ok') {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: '{{ lang._("Success") }}',
                    message: '{{ lang._("Service stopped successfully") }}'
                });
            } else {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: '{{ lang._("Error") }}',
                    message: data.message || '{{ lang._("Failed to stop service") }}'
                });
            }
            setTimeout(updateServiceStatus, 2000);
        }).fail(function() {
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_DANGER,
                title: '{{ lang._("Error") }}',
                message: '{{ lang._("Failed to communicate with service") }}'
            });
            setTimeout(updateServiceStatus, 2000);
        });
    });

    // Service Restart Handler
    $('#service-restart').click(function() {
        $(this).prop('disabled', true);
        $('#service-status').text('{{ lang._("Restarting...") }}');
        
        $.post('/api/abuseipdbchecker/service/restart', function(data) {
            if (data && data.status === 'ok') {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_SUCCESS,
                    title: '{{ lang._("Success") }}',
                    message: '{{ lang._("Service restarted successfully") }}'
                });
            } else {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: '{{ lang._("Error") }}',
                    message: data.message || '{{ lang._("Failed to restart service") }}'
                });
            }
            setTimeout(updateServiceStatus, 3000);
        }).fail(function() {
            BootstrapDialog.show({
                type: BootstrapDialog.TYPE_DANGER,
                title: '{{ lang._("Error") }}',
                message: '{{ lang._("Failed to communicate with service") }}'
            });
            setTimeout(updateServiceStatus, 2000);
        });
    });

    // Settings Validation Handler
    $('#validate-settings').click(function() {
        var errors = [];
        var warnings = [];
        
        var abuseApiKey = $("#abuseipdbchecker\\.api\\.Key").val();
        if (!abuseApiKey || abuseApiKey === "YOUR_API_KEY") {
            errors.push('{{ lang._("AbuseIPDB API key is required") }}');
        }
        
        var dailyLimit = $("#abuseipdbchecker\\.api\\.DailyCheckLimit").val();
        if (dailyLimit && (parseInt(dailyLimit) < 1 || parseInt(dailyLimit) > 1000)) {
            errors.push('{{ lang._("Daily check limit must be between 1 and 1000") }}');
        }
        
        var opnApiKey = $("#abuseipdbchecker\\.general\\.ApiKey").val();
        var opnApiSecret = $("#abuseipdbchecker\\.general\\.ApiSecret").val();
        if (!opnApiKey || !opnApiSecret) {
            warnings.push('{{ lang._("OPNsense API credentials missing - alias management will not work") }}');
        }
        
        var message = '';
        var type = BootstrapDialog.TYPE_SUCCESS;
        
        if (errors.length > 0) {
            type = BootstrapDialog.TYPE_DANGER;
            message += '<strong>{{ lang._("Errors (must fix):") }}</strong><ul>';
            errors.forEach(function(error) {
                message += '<li>' + error + '</li>';
            });
            message += '</ul>';
        }
        
        if (warnings.length > 0) {
            if (type === BootstrapDialog.TYPE_SUCCESS) {
                type = BootstrapDialog.TYPE_WARNING;
            }
            message += '<strong>{{ lang._("Warnings:") }}</strong><ul>';
            warnings.forEach(function(warning) {
                message += '<li>' + warning + '</li>';
            });
            message += '</ul>';
        }
        
        if (errors.length === 0 && warnings.length === 0) {
            message = '{{ lang._("All settings are valid! The service is ready to operate.") }}';
        }
        
        BootstrapDialog.show({
            type: type,
            title: '{{ lang._("Settings Validation") }}',
            message: message
        });
    });
</script>