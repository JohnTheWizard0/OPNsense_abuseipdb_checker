<script>
    $(document).ready(function() {
        
        // Global pagination state
        var currentPages = {
            threats: 1,
            allscannedips: 1
        };
        
        var currentSearch = {
            threats: '',
            allscannedips: ''
        };
        
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
        
        // Helper function to get threat status badge with enhanced status for marked safe
        function getThreatStatusBadge(threatLevel, abuseScore, markedSafe) {
            if (markedSafe) {
                return '<span class="label label-info">Marked Safe (' + abuseScore + '%)</span>';
            }
            
            var level = threatLevel;
            if (typeof threatLevel === 'undefined' || threatLevel === null) {
                if (abuseScore < 40) level = 0;
                else if (abuseScore < 70) level = 1;
                else level = 2;
            }
            
            switch(level) {
                case 0:
                    return '<span class="label label-success">Safe (' + abuseScore + '%)</span>';
                case 1:
                    return '<span class="label label-warning">Suspicious (' + abuseScore + '%)</span>';
                case 2:
                    return '<span class="label label-danger">Malicious (' + abuseScore + '%)</span>';
                default:
                    return '<span class="label label-default">Unknown (' + abuseScore + '%)</span>';
            }
        }
        
        // Helper function to create pagination controls
        function createPaginationControls(containerId, pagination, onPageClick) {
            var container = $('#' + containerId);
            container.empty();
            
            if (!pagination || pagination.total_pages <= 1) {
                return;
            }
            
            var paginationHtml = '<nav aria-label="Page navigation"><ul class="pagination pagination-sm">';
            
            // Previous button
            if (pagination.has_prev) {
                paginationHtml += '<li><a href="#" data-page="' + (pagination.page - 1) + '">&laquo; Previous</a></li>';
            } else {
                paginationHtml += '<li class="disabled"><span>&laquo; Previous</span></li>';
            }
            
            // Page numbers (show up to 5 pages around current)
            var startPage = Math.max(1, pagination.page - 2);
            var endPage = Math.min(pagination.total_pages, pagination.page + 2);
            
            if (startPage > 1) {
                paginationHtml += '<li><a href="#" data-page="1">1</a></li>';
                if (startPage > 2) {
                    paginationHtml += '<li class="disabled"><span>...</span></li>';
                }
            }
            
            for (var i = startPage; i <= endPage; i++) {
                if (i === pagination.page) {
                    paginationHtml += '<li class="active"><span>' + i + '</span></li>';
                } else {
                    paginationHtml += '<li><a href="#" data-page="' + i + '">' + i + '</a></li>';
                }
            }
            
            if (endPage < pagination.total_pages) {
                if (endPage < pagination.total_pages - 1) {
                    paginationHtml += '<li class="disabled"><span>...</span></li>';
                }
                paginationHtml += '<li><a href="#" data-page="' + pagination.total_pages + '">' + pagination.total_pages + '</a></li>';
            }
            
            // Next button
            if (pagination.has_next) {
                paginationHtml += '<li><a href="#" data-page="' + (pagination.page + 1) + '">Next &raquo;</a></li>';
            } else {
                paginationHtml += '<li class="disabled"><span>Next &raquo;</span></li>';
            }
            
            paginationHtml += '</ul></nav>';
            
            container.html(paginationHtml);
            
            // Bind click events
            container.find('a[data-page]').click(function(e) {
                e.preventDefault();
                var page = parseInt($(this).data('page'));
                onPageClick(page);
            });
        }
        
        // IP Management Functions
        function removeIpFromThreats(ip) {
            BootstrapDialog.confirm({
                title: "{{ lang._('Confirm Remove') }}",
                message: "{{ lang._('Are you sure you want to completely remove ') }}" + ip + "{{ lang._(' from the threats list? This action cannot be undone.') }}",
                type: BootstrapDialog.TYPE_DANGER,
                callback: function(confirmed) {
                    if (confirmed) {
                        $.ajax({
                            url: '/api/abuseipdbchecker/service/removeip',
                            type: 'POST',
                            data: JSON.stringify({'ip': ip}),
                            contentType: 'application/json',
                            success: function(data) {
                                if (data.status === 'ok') {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_SUCCESS,
                                        title: "{{ lang._('Success') }}",
                                        message: "{{ lang._('IP ') }}" + ip + "{{ lang._(' has been removed from threats.') }}"
                                    });
                                    updateThreats(); // Refresh threats list
                                    updateStats(); // Update statistics
                                } else {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_DANGER,
                                        title: "{{ lang._('Error') }}",
                                        message: data.message || "{{ lang._('Failed to remove IP') }}"
                                    });
                                }
                            },
                            error: function() {
                                BootstrapDialog.show({
                                    type: BootstrapDialog.TYPE_DANGER,
                                    title: "{{ lang._('Error') }}",
                                    message: "{{ lang._('Failed to communicate with server') }}"
                                });
                            }
                        });
                    }
                }
            });
        }
        
        function markIpSafe(ip) {
            BootstrapDialog.confirm({
                title: "{{ lang._('Confirm Mark Safe') }}",
                message: "{{ lang._('Are you sure you want to mark ') }}" + ip + "{{ lang._(' as safe? It will still appear in the threats list but marked as safe.') }}",
                type: BootstrapDialog.TYPE_INFO,
                callback: function(confirmed) {
                    if (confirmed) {
                        $.ajax({
                            url: '/api/abuseipdbchecker/service/marksafe',
                            type: 'POST',
                            data: JSON.stringify({'ip': ip, 'marked_by': 'admin'}),
                            contentType: 'application/json',
                            success: function(data) {
                                if (data.status === 'ok') {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_SUCCESS,
                                        title: "{{ lang._('Success') }}",
                                        message: "{{ lang._('IP ') }}" + ip + "{{ lang._(' has been marked as safe.') }}"
                                    });
                                    updateThreats(); // Refresh threats list
                                    updateStats(); // Update statistics
                                } else {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_DANGER,
                                        title: "{{ lang._('Error') }}",
                                        message: data.message || "{{ lang._('Failed to mark IP as safe') }}"
                                    });
                                }
                            },
                            error: function() {
                                BootstrapDialog.show({
                                    type: BootstrapDialog.TYPE_DANGER,
                                    title: "{{ lang._('Error') }}",
                                    message: "{{ lang._('Failed to communicate with server') }}"
                                });
                            }
                        });
                    }
                }
            });
        }
        
        function unmarkIpSafe(ip) {
            BootstrapDialog.confirm({
                title: "{{ lang._('Confirm Unmark Safe') }}",
                message: "{{ lang._('Are you sure you want to restore threat status for ') }}" + ip + "{{ lang._('? It will no longer be marked as safe.') }}",
                type: BootstrapDialog.TYPE_WARNING,
                callback: function(confirmed) {
                    if (confirmed) {
                        $.ajax({
                            url: '/api/abuseipdbchecker/service/unmarksafe',
                            type: 'POST',
                            data: JSON.stringify({'ip': ip}),
                            contentType: 'application/json',
                            success: function(data) {
                                if (data.status === 'ok') {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_SUCCESS,
                                        title: "{{ lang._('Success') }}",
                                        message: "{{ lang._('IP ') }}" + ip + "{{ lang._(' threat status has been restored.') }}"
                                    });
                                    updateThreats(); // Refresh threats list
                                    updateStats(); // Update statistics
                                } else {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_DANGER,
                                        title: "{{ lang._('Error') }}",
                                        message: data.message || "{{ lang._('Failed to unmark IP as safe') }}"
                                    });
                                }
                            },
                            error: function() {
                                BootstrapDialog.show({
                                    type: BootstrapDialog.TYPE_DANGER,
                                    title: "{{ lang._('Error') }}",
                                    message: "{{ lang._('Failed to communicate with server') }}"
                                });
                            }
                        });
                    }
                }
            });
        }

        // Centralized event binding functions
        function bindThreatActionButtons() {
            $('.mark-safe-btn').click(function() {
                markIpSafe($(this).data('ip'));
            });
            
            $('.unmark-safe-btn').click(function() {
                unmarkIpSafe($(this).data('ip'));
            });
            
            $('.remove-ip-btn').click(function() {
                removeIpFromThreats($(this).data('ip'));
            });
        }
        
        function bindConnectionInfoButtons() {
            $('.connection-info-btn').click(function() {
                var ip = $(this).data('ip');
                var connectionDetails = $(this).data('connection-details');
                showConnectionDetails(ip, connectionDetails);
            });
        }

        // Enhanced updateThreats - ALWAYS shows connection button
        function updateThreats(page = null, search = null) {
            if (page !== null) currentPages.threats = page;
            if (search !== null) currentSearch.threats = search;
            
            $("#threats-info").show().text("{{ lang._('Loading threats...') }}");
            $("#recent-threats-table").empty();
            
            var params = {
                page: currentPages.threats,
                limit: 20,
                search: currentSearch.threats,
                include_marked_safe: 'true'
            };
            
            $.get('/api/abuseipdbchecker/service/threats', params, function(data) {
                $("#threats-info").hide();
                
                if (data && data.status === 'ok' && data.threats) {
                    var threatTable = $("#recent-threats-table");
                    threatTable.empty();
                    
                    if (data.threats.length === 0) {
                        threatTable.append('<tr><td colspan="6">{{ lang._("No threats found") }}</td></tr>');
                    } else {
                        $("#threats-info").removeClass("alert-info alert-danger")
                            .addClass("alert-success")
                            .text("{{ lang._('Found ') }}" + data.total_count + "{{ lang._(' threats (page ') }}" + 
                                 currentPages.threats + "{{ lang._(' of ') }}" + (data.pagination ? data.pagination.total_pages : 1) + ")")
                            .show();
                        
                        $.each(data.threats, function(i, threat) {
                            var row = $('<tr>');
                            
                            // Add special styling for marked safe
                            if (threat.marked_safe) {
                                row.addClass('info');
                            }
                            
                            // IP Address with connection info button - ALWAYS show button
                            var ipCell = $('<td>');
                            var connectionDetails = threat.connection_details || '';
                            var connectionButton = createConnectionInfoButton(threat.ip, connectionDetails);
                            var ipContent = threat.ip + ' ' + connectionButton;
                            ipCell.html(ipContent);
                            row.append(ipCell);
                            
                            var statusCell = $('<td>');
                            statusCell.html(getThreatStatusBadge(threat.threat_level, threat.score, threat.marked_safe));
                            row.append(statusCell);
                            
                            row.append($('<td>').text(threat.last_seen));
                            row.append($('<td>').html(getCountryDisplay(threat.country)));
                            row.append($('<td>').text(threat.reports || 0));
                            
                            var actionsCell = $('<td>');
                            var actionButtons = '';
                            
                            if (threat.marked_safe) {
                                actionButtons += '<button class="btn btn-xs btn-warning unmark-safe-btn" data-ip="' + threat.ip + '" title="Restore threat status">{{ lang._("Unmark Safe") }}</button> ';
                                actionButtons += '<span class="text-muted">{{ lang._("Marked by ") }}' + threat.marked_safe_by + '</span>';
                            } else {
                                actionButtons += '<button class="btn btn-xs btn-info mark-safe-btn" data-ip="' + threat.ip + '" title="Mark as safe">{{ lang._("Mark Safe") }}</button> ';
                                actionButtons += '<button class="btn btn-xs btn-danger remove-ip-btn" data-ip="' + threat.ip + '" title="Remove completely">{{ lang._("Remove") }}</button> ';
                            }
                            
                            actionButtons += '<a href="https://www.abuseipdb.com/check/' + threat.ip + '" target="_blank" class="btn btn-xs btn-primary">{{ lang._("View Details") }}</a>';
                            
                            actionsCell.html(actionButtons);
                            row.append(actionsCell);
                            
                            threatTable.append(row);
                        });
                        
                        // Bind all event handlers
                        bindThreatActionButtons();
                        bindConnectionInfoButtons();
                        
                        // Create pagination controls
                        if (data.pagination) {
                            createPaginationControls('threats-pagination', data.pagination, function(page) {
                                updateThreats(page);
                            });
                        }
                    }
                } else {
                    $("#threats-info").removeClass("alert-info alert-success")
                        .addClass("alert-danger")
                        .text(data.message || "{{ lang._('Error retrieving threats') }}")
                        .show();
                    $("#recent-threats-table").append('<tr><td colspan="6">{{ lang._("Error loading threats") }}</td></tr>');
                }
            }).fail(function() {
                console.log('Threats update failed');
                $("#threats-info").removeClass("alert-info alert-success")
                    .addClass("alert-danger")
                    .text("{{ lang._('Failed to communicate with server') }}")
                    .show();
            });
        }

        // Enhanced updateAllScannedIPs - ALWAYS shows connection button
        function updateAllScannedIPs(page = null, search = null) {
            if (page !== null) currentPages.allscannedips = page;
            if (search !== null) currentSearch.allscannedips = search;
            
            $("#all-scanned-ips-info").show().text("{{ lang._('Loading all scanned IPs...') }}");
            $("#all-scanned-ips-table").empty();
            
            var params = {
                page: currentPages.allscannedips,
                limit: 20,
                search: currentSearch.allscannedips
            };
            
            $.get('/api/abuseipdbchecker/service/allips', params, function(data) {
                $("#all-scanned-ips-info").hide();
                
                if (data && data.status === 'ok' && data.ips) {
                    var ipTable = $("#all-scanned-ips-table");
                    ipTable.empty();
                    
                    if (data.ips.length === 0) {
                        ipTable.append('<tr><td colspan="6">{{ lang._("No IPs have been scanned yet") }}</td></tr>');
                    } else {
                        $("#all-scanned-ips-info").removeClass("alert-info alert-danger")
                            .addClass("alert-success")
                            .text("{{ lang._('Found ') }}" + data.total_count + "{{ lang._(' scanned IPs (page ') }}" + 
                                 currentPages.allscannedips + "{{ lang._(' of ') }}" + (data.pagination ? data.pagination.total_pages : 1) + ")")
                            .show();
                        
                        $.each(data.ips, function(i, ipData) {
                            var row = $('<tr>');
                            
                            // Add special styling for marked safe
                            if (ipData.marked_safe) {
                                row.addClass('info');
                            }
                            
                            // IP Address with connection info button - ALWAYS show button
                            var ipCell = $('<td>');
                            var connectionDetails = ipData.connection_details || '';
                            var connectionButton = createConnectionInfoButton(ipData.ip, connectionDetails);
                            var ipContent = ipData.ip + ' ' + connectionButton;
                            ipCell.html(ipContent);
                            row.append(ipCell);
                            
                            var statusCell = $('<td>');
                            statusCell.html(getThreatStatusBadge(ipData.threat_level, ipData.abuse_score, ipData.marked_safe));
                            row.append(statusCell);
                            
                            row.append($('<td>').text(ipData.last_checked));
                            row.append($('<td>').html(getCountryDisplay(ipData.country)));
                            row.append($('<td>').text(ipData.reports || 0));
                            
                            var actionsCell = $('<td>');
                            actionsCell.html(
                                '<button class="btn btn-xs btn-primary test-ip-btn" data-ip="' + ipData.ip + '">{{ lang._("Re-test") }}</button> ' +
                                '<a href="https://www.abuseipdb.com/check/' + ipData.ip + '" target="_blank" class="btn btn-xs btn-info">{{ lang._("View Details") }}</a>'
                            );
                            row.append(actionsCell);
                            
                            ipTable.append(row);
                        });
                        
                        // Bind all event handlers
                        $('.test-ip-btn').click(function() {
                            var ip = $(this).data('ip');
                            $("#ipToTest").val(ip);
                            $('a[href="#testip"]').tab('show');
                            $("#testIpBtn").click();
                        });
                        
                        bindConnectionInfoButtons();
                        
                        // Create pagination controls
                        if (data.pagination) {
                            createPaginationControls('allips-pagination', data.pagination, function(page) {
                                updateAllScannedIPs(page);
                            });
                        }
                    }
                } else {
                    $("#all-scanned-ips-info").removeClass("alert-info alert-success")
                        .addClass("alert-danger")
                        .text(data.message || "{{ lang._('Error retrieving scanned IPs') }}")
                        .show();
                    $("#all-scanned-ips-table").append('<tr><td colspan="6">{{ lang._("Error loading scanned IPs") }}</td></tr>');
                }
            }).fail(function() {
                console.log('All scanned IPs update failed');
                $("#all-scanned-ips-info").removeClass("alert-info alert-success")
                    .addClass("alert-danger")
                    .text("{{ lang._('Failed to communicate with server') }}")
                    .show();
            });
        }

        // Search functionality
        $('#threats-search').on('keyup', function() {
            var searchTerm = $(this).val().trim();
            currentPages.threats = 1; // Reset to first page
            updateThreats(1, searchTerm);
        });
        
        $('#allips-search').on('keyup', function() {
            var searchTerm = $(this).val().trim();
            currentPages.allscannedips = 1; // Reset to first page
            updateAllScannedIPs(1, searchTerm);
        });

        // Load initial data
        var data_get_map = {
            'frm_general': "/api/abuseipdbchecker/settings/get",
            'frm_network': "/api/abuseipdbchecker/settings/get",
            'frm_api': "/api/abuseipdbchecker/settings/get",
            'frm_alias': "/api/abuseipdbchecker/settings/get"
        };
        mapDataToFormUI(data_get_map).done(function() {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            updateStats();
        });

        // Helper function to format connection details for popup
        function formatConnectionDetails(connectionDetails) {
            if (!connectionDetails || connectionDetails === '') {
                return '<span class="text-muted">No connection details available</span>';
            }
            
            // Split by pipe separator and format each connection
            var connections = connectionDetails.split('|');
            var formatted = connections.map(function(conn) {
                return '<div class="connection-detail">' + conn + '</div>';
            }).join('');
            
            return formatted;
        }
        
        // Helper function to create connection info button
        function createConnectionInfoButton(ip, connectionDetails) {
            var buttonId = 'conn-btn-' + ip.replace(/\./g, '-');
            var hasData = connectionDetails && connectionDetails !== '';
            var buttonClass = hasData ? 'btn btn-xs btn-info' : 'btn btn-xs btn-secondary';
            var title = hasData ? 'View connection details' : 'No connection data available';
            var dataAttr = hasData ? connectionDetails : 'NO_DATA';
            
            return '<button class="' + buttonClass + ' connection-info-btn" ' +
                   'data-ip="' + ip + '" ' +
                   'data-connection-details="' + dataAttr + '" ' +
                   'id="' + buttonId + '" ' +
                   'title="' + title + '">' +
                   '<i class="fa fa-info-circle"></i>' +
                   '</button>';
        }
        
        // Connection details popup handler
        function showConnectionDetails(ip, connectionDetails) {
            var content;
            var dialogType = BootstrapDialog.TYPE_INFO;
            
            if (!connectionDetails || connectionDetails === '' || connectionDetails === 'NO_DATA') {
                content = '<div class="connection-details-popup">' +
                         '<div class="alert alert-warning">' +
                         '<i class="fa fa-exclamation-triangle"></i> ' +
                         '{{ lang._("No connection data available for this IP.") }}<br>' +
                         '<small class="text-muted">{{ lang._("This IP was checked before connection tracking was implemented.") }}</small>' +
                         '</div>' +
                         '</div>';
                dialogType = BootstrapDialog.TYPE_WARNING;
            } else {
                var formattedDetails = formatConnectionDetails(connectionDetails);
                content = '<div class="connection-details-popup">' +
                         '<h5>{{ lang._("Source → Destination Connections:") }}</h5>' +
                         formattedDetails +
                         '<div class="text-muted" style="margin-top: 15px;">' +
                         '<small><i class="fa fa-info-circle"></i> {{ lang._("Shows external IP connections to your internal network") }}</small>' +
                         '</div>' +
                         '</div>';
            }
            
            BootstrapDialog.show({
                type: dialogType,
                title: "{{ lang._('Connection Details for ') }}" + ip,
                message: content,
                buttons: [{
                    label: "{{ lang._('Close') }}",
                    action: function(dialogRef) {
                        dialogRef.close();
                    }
                }]
            });
        }

        // Save Settings Function
        $("#saveAct").click(function() {
            console.log("Save button clicked");
    
            $("#saveAct_progress").addClass("fa fa-spinner fa-pulse");
            
            var data = {
                'abuseipdbchecker': {}
            };
            
            // Extract data from each form
            ["general", "network", "api", "alias"].forEach(function(section) {
                var formData = getFormData("frm_" + section);
                
                if (formData && formData.abuseipdbchecker && formData.abuseipdbchecker[section]) {
                    data.abuseipdbchecker[section] = formData.abuseipdbchecker[section];
                }
            });

            // Enhanced validation
            var apiKey = $("#abuseipdbchecker\\.api\\.Key").val();
            var dailyLimit = $("#abuseipdbchecker\\.api\\.DailyCheckLimit").val();
            var opnApiKey = $("#abuseipdbchecker\\.general\\.ApiKey").val();
            var opnApiSecret = $("#abuseipdbchecker\\.general\\.ApiSecret").val();
            
            if (!apiKey || apiKey === "YOUR_API_KEY") {
                $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: "{{ lang._('Configuration Error') }}",
                    message: "{{ lang._('AbuseIPDB API key is required. Please configure a valid API key in the API tab before starting the service.') }}"
                });
                return;
            }
            
            if (dailyLimit && (parseInt(dailyLimit) < 1 || parseInt(dailyLimit) > 1000)) {
                $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: "{{ lang._('Configuration Error') }}",
                    message: "{{ lang._('Daily Check Limit must be between 1 and 1000.') }}"
                });
                return;
            }
            
            if (!opnApiKey || !opnApiSecret) {
                $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_WARNING,
                    title: "{{ lang._('Warning') }}",
                    message: "{{ lang._('OPNsense API credentials are missing. The service will work but alias management will be disabled. You can add API credentials later in the General tab.') }}",
                    buttons: [{
                        label: "{{ lang._('Continue Anyway') }}",
                        action: function(dialogRef) {
                            dialogRef.close();
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
            
            saveSettings(data);
        });

        function saveSettings(data) {
            ajaxCall(
                "/api/abuseipdbchecker/settings/set",
                data,
                function(data, status) {
                    $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
                    
                    if (data.result === "saved") {
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_SUCCESS,
                            title: "{{ lang._('Settings saved') }}",
                            message: "{{ lang._('All settings have been saved successfully. The service will automatically create/update the MaliciousIPs alias if enabled.') }}"
                        });
                        
                        updateStats();
                        updateThreats();
                        updateAllScannedIPs();
                        updateLogs();
                        updateServiceStatus();
                    } else {
                        BootstrapDialog.show({
                            type: BootstrapDialog.TYPE_DANGER,
                            title: "{{ lang._('Error') }}",
                            message: "{{ lang._('There was an error saving settings: ') }}" + (data.message || "{{ lang._('Unknown error') }}")
                        });
                    }
                }
            );
        }

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
            
            var ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
            if (!ipRegex.test(ip)) {
                BootstrapDialog.show({
                    type: BootstrapDialog.TYPE_DANGER,
                    title: "{{ lang._('Error') }}",
                    message: "{{ lang._('Invalid IP address format') }}"
                });
                return;
            }
            
            $("#testIpBtn").prop("disabled", true);
            $("#testResultAlert").removeClass("hidden alert-success alert-danger alert-warning")
                .addClass("alert-info")
                .text("{{ lang._('Testing IP address...') }}");
            $("#testResults").removeClass("hidden");
            $("#testResultTable").addClass("hidden");
            
            $.ajax({
                url: "/api/abuseipdbchecker/service/testip",
                type: "POST",
                data: JSON.stringify({"ip": ip}),
                contentType: "application/json",
                dataType: "json",
                timeout: 30000,
                success: function(data, status) {
                    $("#testIpBtn").prop("disabled", false);
                    
                    if (data && data.status === 'ok') {
                        var threatLevel = data.threat_level !== undefined ? data.threat_level : classifyThreatLevel(data.abuse_score);
                        var alertClass = "alert-success";
                        var alertText = "{{ lang._('IP appears to be safe with score ') }}" + data.abuse_score + "%";
                        
                        if (threatLevel === 1) {
                            alertClass = "alert-warning";
                            alertText = "{{ lang._('Suspicious IP detected with score ') }}" + data.abuse_score + "%";
                        } else if (threatLevel === 2) {
                            alertClass = "alert-danger";
                            alertText = "{{ lang._('Malicious IP detected with score ') }}" + data.abuse_score + "%";
                        }
                        
                        $("#testResultAlert").removeClass("alert-info alert-danger alert-warning alert-success")
                            .addClass(alertClass)
                            .text(alertText);
                        
                        $("#result-ip").text(data.ip);
                        var threatLevel = data.threat_level !== undefined ? data.threat_level : classifyThreatLevel(data.abuse_score);
                        $("#result-threat").html(getThreatStatusBadge(threatLevel, data.abuse_score));
                        $("#result-score").text(data.abuse_score + "%");
                        $("#result-country").html(getCountryDisplay(data.country));
                        $("#result-isp").text(data.isp);
                        $("#result-domain").text(data.domain);
                        $("#result-reports").text(data.reports);
                        $("#result-last-reported").text(data.last_reported);
                        $("#result-abusedb-link").html('<a href="https://www.abuseipdb.com/check/' + data.ip + 
                        '" target="_blank" class="btn btn-xs btn-primary"><i class="fa fa-external-link"></i> {{ lang._("View Full Report") }}</a>');
                                                
                        $("#testResultTable").removeClass("hidden");
                        
                        updateStats();
                        updateThreats();
                        updateAllScannedIPs();
                        updateLogs();
                        updateExternalIPs();

                    } else {
                        $("#testResultAlert").removeClass("alert-info alert-success alert-warning")
                            .addClass("alert-danger")
                            .text(data.message || "{{ lang._('Error testing IP address') }}");
                        $("#testResultTable").addClass("hidden");
                    }
                },
                error: function(xhr, status, error) {
                    $("#testIpBtn").prop("disabled", false);
                    
                    var errorMsg = "{{ lang._('Error communicating with server') }}";
                    if (xhr.status) {
                        errorMsg += " (HTTP " + xhr.status + ")";
                    }
                    
                    $("#testResultAlert").removeClass("alert-info alert-success alert-warning")
                        .addClass("alert-danger")
                        .text(errorMsg);
                    $("#testResultTable").addClass("hidden");
                }
            });
        });
        
        // Helper functions
        function classifyThreatLevel(abuseScore) {
            if (abuseScore < 40) return 0;
            else if (abuseScore < 70) return 1;
            else return 2;
        }
        
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
                                statusCell.html('<span class="label label-danger">{{ lang._("Malicious") }}</span>');
                            } else if (ipData.threat_status === 'Suspicious') {
                                statusCell.html('<span class="label label-warning">{{ lang._("Suspicious") }}</span>');
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
                        
                        $('.test-ip-btn').click(function() {
                            var ip = $(this).data('ip');
                            $("#ipToTest").val(ip);
                            $('a[href="#testip"]').tab('show');
                            $("#testIpBtn").click();
                        });
                    }
                } else {
                    $("#external-ips-info").removeClass("alert-info alert-success")
                        .addClass("alert-danger")
                        .text(data.message || "{{ lang._('Error retrieving external IPs') }}")
                        .show();
                    $("#external-ips-table").append('<tr><td colspan="5">{{ lang._("Error loading external IPs") }}</td></tr>');
                }
            });
        }

        function updateStats() {
            ajaxCall("/api/abuseipdbchecker/service/stats", {}, function(data) {
                if (data && data.status === 'ok') {
                    $("#total-ips-checked").text(data.total_ips || 0);
                    $("#total-threats").text(data.total_threats || 0);
                    if (data.threat_breakdown) {
                        $("#total-threats").attr('title', data.threat_breakdown);
                    }
                    $("#checks-today").text(data.daily_checks || 0);
                    $("#last-run").text(data.last_check || 'Never');
                }
            }, function() {
                console.log('Stats update failed');
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

        // Service Management Functions
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
        
        // Enhanced refresh functions
        $("#refreshStats").click(updateStats);
        $("#refreshExternalIPs").click(updateExternalIPs);
        $("#refreshLogs").click(updateLogs);
        
        $("#refreshThreats").click(function() {
            currentPages.threats = 1;
            currentSearch.threats = '';
            $('#threats-search').val('');
            updateThreats();
        });
        
        $("#refreshAllScannedIPs").click(function() {
            currentPages.allscannedips = 1;
            currentSearch.allscannedips = '';
            $('#allips-search').val('');
            updateAllScannedIPs();
        });
        
        // Initialize service status monitoring
        updateServiceStatus();
        setInterval(updateServiceStatus, 15000);
        
        // Initialize all data
        updateStats();
        updateExternalIPs();
        updateThreats();
        updateAllScannedIPs();
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
    
    .table .country-flag-icon {
        width: 1.2em;
        height: 0.9em;
    }
    
    .fi {
        border-radius: 2px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }
    
    /* Enhanced styling for marked safe rows */
    .table tbody tr.info {
        background-color: #d9edf7;
    }
    
    .pagination {
        margin: 10px 0;
    }
    
    .search-container {
        margin-bottom: 15px;
    }
    
    .search-container input {
        width: 100%;
        max-width: 300px;
    }

    /* Add this CSS to index.volt <style> section */

    .connection-info-btn {
        margin-left: 5px;
        padding: 2px 6px;
        font-size: 11px;
    }

    .connection-details-popup {
        max-width: 500px;
    }

    .connection-details-popup h5 {
        margin-bottom: 15px;
        color: #333;
        border-bottom: 1px solid #eee;
        padding-bottom: 5px;
    }

    .connection-detail {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 3px;
        padding: 8px 12px;
        margin-bottom: 5px;
        font-family: monospace;
        font-size: 12px;
        color: #495057;
    }

    .connection-detail:last-child {
        margin-bottom: 0;
    }

    /* Enhanced table styling */
    .table th .fa-info-circle {
        margin-left: 5px;
        cursor: help;
    }

    .btn-secondary {
        background-color: #6c757d;
        border-color: #6c757d;
        color: #fff;
    }

    .btn-secondary:hover {
        background-color: #5a6268;
        border-color: #545b62;
    }

    .alert-warning i {
        margin-right: 8px;
    }

</style>
    
<!-- Main Settings Tabs -->
<ul class="nav nav-tabs" role="tablist" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#network">{{ lang._('Network') }}</a></li>
    <li><a data-toggle="tab" href="#api">{{ lang._('API') }}</a></li>
    <li><a data-toggle="tab" href="#alias">{{ lang._('Alias') }}</a></li>
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

    <!-- Alias Settings -->
    <div id="alias" class="tab-pane fade">
        <div class="content-box">
            {{ partial("layout_partials/base_form",['fields':aliasForm,'id':'frm_alias','parent':'abuseipdbchecker']) }}
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

<!-- Service Control Section -->
<div class="content-box" style="margin-top: 10px;">
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-12">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">{{ lang._('Service Control') }}</h3>
                    </div>
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-md-3">
                                <strong>{{ lang._('Service Status') }}:</strong>
                                <span id="service-status" class="text-muted">{{ lang._('Checking...') }}</span>
                            </div>
                            <div class="col-md-9">
                                <button id="service-start" class="btn btn-success btn-sm" disabled>
                                    <i class="fa fa-play"></i> {{ lang._('Start') }}
                                </button>
                                <button id="service-stop" class="btn btn-danger btn-sm" disabled>
                                    <i class="fa fa-stop"></i> {{ lang._('Stop') }}
                                </button>
                                <button id="service-restart" class="btn btn-warning btn-sm" disabled>
                                    <i class="fa fa-refresh"></i> {{ lang._('Restart') }}
                                </button>
                                <button id="validate-settings" class="btn btn-info btn-sm">
                                    <i class="fa fa-check-circle"></i> {{ lang._('Validate Settings') }}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Enhanced Statistics & Monitoring Section -->
<div class="content-box" style="margin-top: 20px;">
    <ul class="nav nav-tabs" data-tabs="tabs" id="abuseipdb-tabs">
        <li class="active"><a data-toggle="tab" href="#stats">{{ lang._('Statistics') }}</a></li>
        <li><a data-toggle="tab" href="#externalips">{{ lang._('External IPs') }}</a></li>
        <li><a data-toggle="tab" href="#allscannedips">{{ lang._('All Scanned IPs') }}</a></li>
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
                                    <td>{{ lang._('Total Threats Detected') }} <i class="fa fa-info-circle" title="Counts threats included in MaliciousIPs alias based on current settings"></i></td>
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
        
        <!-- Enhanced All Scanned IPs Tab -->
        <div id="allscannedips" class="tab-pane fade">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-6">
                        <div class="search-container">
                            <input type="text" id="allips-search" class="form-control" placeholder="{{ lang._('Search by IP address...') }}">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <button id="refreshAllScannedIPs" class="btn btn-xs btn-primary pull-right">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                        <p class="text-muted">{{ lang._('All IPs checked against AbuseIPDB with connection details') }}</p>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <div id="all-scanned-ips-info" class="alert alert-info" style="display: none;">
                            {{ lang._('Loading all scanned IPs...') }}
                        </div>
                        <table class="table table-striped table-condensed">
                            <thead>
                                <tr>
                                    <th>{{ lang._('IP Address') }} <i class="fa fa-info-circle text-muted" title="Click info button next to IP to view connection details"></i></th>
                                    <th>{{ lang._('Status') }}</th>
                                    <th>{{ lang._('Last Checked') }}</th>
                                    <th>{{ lang._('Country') }}</th>
                                    <th>{{ lang._('Reports') }}</th>
                                    <th>{{ lang._('Actions') }}</th>
                                </tr>
                            </thead>
                            <tbody id="all-scanned-ips-table">
                                <!-- Dynamically populated -->
                            </tbody>
                        </table>
                        <div id="allips-pagination"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Enhanced Recent Threats Tab -->
        <div id="threats" class="tab-pane fade">
            <div class="container-fluid">
                <div class="row">
                    <div class="col-md-6">
                        <div class="search-container">
                            <input type="text" id="threats-search" class="form-control" placeholder="{{ lang._('Search by IP address...') }}">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <button id="refreshThreats" class="btn btn-xs btn-primary pull-right">
                            <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
                        </button>
                        <p class="text-muted">{{ lang._('Malicious IPs detected by AbuseIPDB checks with management options') }}</p>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <div id="threats-info" class="alert alert-info" style="display: none;">
                            {{ lang._('Loading threats...') }}
                        </div>
                        <table class="table table-striped table-condensed">
                            <thead>
                                <tr>
                                    <th>{{ lang._('IP Address') }} <i class="fa fa-info-circle text-muted" title="Click info button next to IP to view connection details"></i></th>
                                    <th>{{ lang._('Status') }}</th>
                                    <th>{{ lang._('Last Checked') }}</th>
                                    <th>{{ lang._('Country') }}</th>
                                    <th>{{ lang._('Reports') }}</th>
                                    <th>{{ lang._('Actions') }}</th>
                                </tr>
                            </thead>
                            <tbody id="recent-threats-table">
                                <!-- Dynamically populated -->
                            </tbody>
                        </table>
                        <div id="threats-pagination"></div>
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
        
        <!-- [Keep existing External IPs, Statistics, and Logs tabs unchanged] -->
    </div>
</div>