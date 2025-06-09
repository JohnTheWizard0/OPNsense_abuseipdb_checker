<script>
	// ================================
	// CONFIGURATION MANAGEMENT MODULE
	// ================================

	// Load initial configuration data

	function loadInitialConfiguration() {
		var data_get_map = {
			'frm_general': "/api/abuseipdbchecker/settings/get",
			'frm_network': "/api/abuseipdbchecker/settings/get",
			'frm_api': "/api/abuseipdbchecker/settings/get",
			'frm_alias': "/api/abuseipdbchecker/settings/get",
			'frm_ntfy': "/api/abuseipdbchecker/settings/get"
		};
		
		mapDataToFormUI(data_get_map).done(function() {
			formatTokenizersUI();
			$('.selectpicker').selectpicker('refresh');
			updateStats();
		});
	}

	// Settings validation function
	function validateSettings() {
		var apiKey = $("#abuseipdbchecker\\.api\\.Key").val();
		var dailyLimit = $("#abuseipdbchecker\\.api\\.DailyCheckLimit").val();
		var opnApiKey = $("#abuseipdbchecker\\.general\\.ApiKey").val();
		var opnApiSecret = $("#abuseipdbchecker\\.general\\.ApiSecret").val();
		
		var errors = [];
		var warnings = [];
		
		// Critical validations
		if (!apiKey || apiKey === "YOUR_API_KEY") {
			errors.push("AbuseIPDB API key is required. Please configure a valid API key in the API tab before starting the service.");
		}
		
		if (dailyLimit && (parseInt(dailyLimit) < 1 || parseInt(dailyLimit) > 1000)) {
			errors.push("Daily Check Limit must be between 1 and 1000.");
		}
		
		// Warning validations
		if (!opnApiKey || !opnApiSecret) {
			warnings.push("OPNsense API credentials are missing. The service will work but alias management will be disabled. You can add API credentials later in the General tab.");
		}
		
		return {
			errors: errors,
			warnings: warnings,
			isValid: errors.length === 0
		};
	}

	// FIXED: Proper POST request function
	function saveSettings(data) {
		console.log("Sending POST request with data:", data);
		
		$.ajax({
			url: "/api/abuseipdbchecker/settings/set",
			type: "POST",
			data: data,
			dataType: "json",
			success: function(response, status) {
				$("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
				console.log("Save response:", response);
				
				if (response.result === "saved") {
					BootstrapDialog.show({
						type: BootstrapDialog.TYPE_SUCCESS,
						title: "{{ lang._('Settings saved') }}",
						message: "{{ lang._('All settings have been saved successfully. The service will automatically create/update the MaliciousIPs alias if enabled.') }}"
					});
					
					// Refresh all data after successful save
					updateStats();
					updateThreats();
					updateAllScannedIPs();
					updateLogs();
					updateServiceStatus();
				} else {
					BootstrapDialog.show({
						type: BootstrapDialog.TYPE_DANGER,
						title: "{{ lang._('Error') }}",
						message: "{{ lang._('There was an error saving settings: ') }}" + (response.message || "{{ lang._('Unknown error') }}")
					});
				}
			},
			error: function(xhr, status, error) {
				$("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
				console.error("Save request failed:", xhr, status, error);
				BootstrapDialog.show({
					type: BootstrapDialog.TYPE_DANGER,
					title: "{{ lang._('Error') }}",
					message: "{{ lang._('Failed to communicate with server: ') }}" + error
				});
			}
		});
	}

	// Main save handler
	$("#saveAct").click(function() {
		console.log("Save button clicked");

		$("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
		
		var data = {
			'abuseipdbchecker': {}
		};
		
		// Extract data from each form
		["general", "network", "api", "alias", "ntfy"].forEach(function(section) {
			var formData = getFormData("frm_" + section);
			
			if (formData && formData.abuseipdbchecker && formData.abuseipdbchecker[section]) {
				data.abuseipdbchecker[section] = formData.abuseipdbchecker[section];
			}
		});

		console.log("Extracted form data:", data);

		// Validate settings before saving
		var validation = validateSettings();
		
		if (!validation.isValid) {
			$("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
			BootstrapDialog.show({
				type: BootstrapDialog.TYPE_DANGER,
				title: "{{ lang._('Configuration Error') }}",
				message: validation.errors.join('<br>')
			});
			return;
		}
		
		// Handle warnings with user choice
		if (validation.warnings.length > 0) {
			$("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
			BootstrapDialog.show({
				type: BootstrapDialog.TYPE_WARNING,
				title: "{{ lang._('Warning') }}",
				message: validation.warnings.join('<br>'),
				buttons: [{
					label: "{{ lang._('Continue Anyway') }}",
					action: function(dialogRef) {
						dialogRef.close();
						$("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
						saveSettings(data);
					}
				}, {
					label: "{{ lang._('Cancel') }}",
					action: function(dialogRef) {
						dialogRef.close();
					}
				}]
			});
			return;
		}
		
		// Save settings if validation passes
		saveSettings(data);
	});

	// ntfy Test Handler
	$('#test-ntfy').click(function() {
		var $button = $(this);
		var $result = $('#ntfy-test-result');
		
		// Validate required fields
		var enabled = $("#abuseipdbchecker\\.ntfy\\.Enabled").is(':checked');
		var server = $("#abuseipdbchecker\\.ntfy\\.Server").val();
		var topic = $("#abuseipdbchecker\\.ntfy\\.Topic").val();
		
		if (!enabled) {
			$result.removeClass('alert-success alert-danger').addClass('alert-warning')
				.text('{{ lang._("ntfy notifications are disabled. Enable them first.") }}')
				.show();
			return;
		}
		
		if (!server || !topic) {
			$result.removeClass('alert-success alert-warning').addClass('alert-danger')
				.text('{{ lang._("Server URL and Topic are required.") }}')
				.show();
			return;
		}
		
		// Disable button and show loading
		$button.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Sending...") }}');
		$result.hide();
		
		// Send test notification
		$.ajax({
			url: '/api/abuseipdbchecker/service/testntfy',
			type: 'POST',
			data: JSON.stringify({
				server: server,
				topic: topic,
				token: $("#abuseipdbchecker\\.ntfy\\.Token").val(),
				priority: $("#abuseipdbchecker\\.ntfy\\.Priority").val()
			}),
			contentType: 'application/json',
			timeout: 15000,
			success: function(data) {
				$button.prop('disabled', false).html('<i class="fa fa-paper-plane"></i> {{ lang._("Send Test Notification") }}');
				
				if (data.status === 'success') {
					$result.removeClass('alert-danger alert-warning').addClass('alert-success')
						.html('<i class="fa fa-check"></i> {{ lang._("Test notification sent successfully!") }}<br>' +
								'<small>{{ lang._("Check your ntfy client for the test message.") }}</small>')
						.show();
				} else {
					$result.removeClass('alert-success alert-warning').addClass('alert-danger')
						.html('<i class="fa fa-exclamation-triangle"></i> {{ lang._("Test failed: ") }}' + 
								(data.message || '{{ lang._("Unknown error") }}'))
						.show();
				}
			},
			error: function(xhr, status, error) {
				$button.prop('disabled', false).html('<i class="fa fa-paper-plane"></i> {{ lang._("Send Test Notification") }}');
				$result.removeClass('alert-success alert-warning').addClass('alert-danger')
					.html('<i class="fa fa-exclamation-triangle"></i> {{ lang._("Connection failed: ") }}' + error)
					.show();
			}
		});
	});

	// Initialize configuration loading when document is ready
	$(document).ready(function() {
		loadInitialConfiguration();
	});
</script>