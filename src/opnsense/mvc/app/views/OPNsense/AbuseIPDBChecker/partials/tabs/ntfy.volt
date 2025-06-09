<!-- ntfy Notifications -->
<div id="ntfy" class="tab-pane fade">
    <div class="content-box">
        {{ partial("layout_partials/base_form",['fields':ntfyForm,'id':'frm_ntfy','parent':'abuseipdbchecker']) }}
        
        <!-- Test Section -->
        <div class="row" style="margin-top: 20px;">
            <div class="col-md-12">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">{{ lang._('Test ntfy Configuration') }}</h3>
                    </div>
                    <div class="panel-body">
                        <p class="text-muted">{{ lang._('Send a test notification to verify your ntfy configuration is working correctly.') }}</p>
                        <button id="test-ntfy" class="btn btn-info">
                            <i class="fa fa-paper-plane"></i> {{ lang._('Send Test Notification') }}
                        </button>
                        <div id="ntfy-test-result" class="alert" style="display: none; margin-top: 15px;" role="alert"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Configuration Help -->
        <div class="row" style="margin-top: 20px;">
            <div class="col-md-12">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">{{ lang._('ntfy Setup Guide') }}</h3>
                    </div>
                    <div class="panel-body">
                        <h4>{{ lang._('Quick Setup:') }}</h4>
                        <ol>
                            <li>{{ lang._('Choose a unique topic name (e.g., "myserver-security-alerts")') }}</li>
                            <li>{{ lang._('For public notifications: Use https://ntfy.sh as server') }}</li>
                            <li>{{ lang._('For private notifications: Set up your own ntfy server or use authentication') }}</li>
                            <li>{{ lang._('Configure which threat levels to notify on') }}</li>
                            <li>{{ lang._('Test your configuration using the button above') }}</li>
                        </ol>
                        
                        <h4>{{ lang._('Security Recommendations:') }}</h4>
                        <ul>
                            <li>{{ lang._('Use a unique, hard-to-guess topic name') }}</li>
                            <li>{{ lang._('Consider using access tokens for sensitive environments') }}</li>
                            <li>{{ lang._('For production use, consider self-hosting ntfy') }}</li>
                        </ul>
                        
                        <h4>{{ lang._('Notification Examples:') }}</h4>
                        <div class="well well-sm">
                            <strong>{{ lang._('Malicious IP:') }}</strong><br>
                            🚨 NEW MALICIOUS IP Detected<br>
                            Host: 192.168.1.100<br>
                            Threat Level: MALICIOUS (85%)<br>
                            Country: Unknown<br>
                            Action: Added to MaliciousIPs alias<br>
                            Connections: Port 443, Port 80
                        </div>
                        
                        <div class="well well-sm">
                            <strong>{{ lang._('Suspicious IP:') }}</strong><br>
                            ⚠️ NEW SUSPICIOUS IP Detected<br>
                            Host: 10.0.0.50<br>
                            Threat Level: SUSPICIOUS (55%)<br>
                            Country: US<br>
                            Action: Monitored (not blocked)<br>
                            Connections: Port 22
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>