<script>
    // ================================
    // UPDATE FUNCTIONS MODULE
    // ================================
    
    // Helper function to get country flag and name
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
    
    // Helper function to get threat status badge
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
                                updateThreats();
                                updateStats();
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
                                updateThreats();
                                updateStats();
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
                                updateThreats();
                                updateStats();
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

    // ================================
    // MAIN UPDATE FUNCTIONS - FIXED
    // ================================

    function updateThreats(page = null, search = null) {
        if (page !== null) window.AbuseIPDB.currentPages.threats = page;
        if (search !== null) window.AbuseIPDB.currentSearch.threats = search;
        
        $("#threats-info").show().text("{{ lang._('Loading threats...') }}");
        $("#recent-threats-table").empty();
        
        var params = {
            page: window.AbuseIPDB.currentPages.threats,
            limit: 20,
            search: window.AbuseIPDB.currentSearch.threats,
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
                             window.AbuseIPDB.currentPages.threats + "{{ lang._(' of ') }}" + (data.pagination ? data.pagination.total_pages : 1) + ")")
                        .show();
                    
                    $.each(data.threats, function(i, threat) {
                        var row = $('<tr>');
                        
                        if (threat.marked_safe) {
                            row.addClass('info');
                        }
                        
                        // IP Address with connection info button - LEFT POSITIONED
                        var ipCell = $('<td>');
                        var connectionDetails = threat.connection_details || '';
                        var connectionButton = createConnectionInfoButton(threat.ip, connectionDetails);
                        var ipContent = connectionButton + ' ' + threat.ip; // BUTTON FIRST
                        ipCell.html(ipContent);
                        row.append(ipCell);
                        
                        var statusCell = $('<td>');
                        statusCell.html(getThreatStatusBadge(threat.threat_level, threat.abuse_score, threat.marked_safe));
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
                    
                    bindThreatActionButtons();
                    bindConnectionInfoButtons();
                    
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
            $("#threats-info").removeClass("alert-info alert-success")
                .addClass("alert-danger")
                .text("{{ lang._('Failed to communicate with server') }}")
                .show();
        });
    }

    function updateAllScannedIPs(page = null, search = null) {
        if (page !== null) window.AbuseIPDB.currentPages.allscannedips = page;
        if (search !== null) window.AbuseIPDB.currentSearch.allscannedips = search;
        
        $("#all-scanned-ips-info").show().text("{{ lang._('Loading all scanned IPs...') }}");
        $("#all-scanned-ips-table").empty();
        
        var params = {
            page: window.AbuseIPDB.currentPages.allscannedips,
            limit: 20,
            search: window.AbuseIPDB.currentSearch.allscannedips
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
                             window.AbuseIPDB.currentPages.allscannedips + "{{ lang._(' of ') }}" + (data.pagination ? data.pagination.total_pages : 1) + ")")
                        .show();
                    
                    $.each(data.ips, function(i, ipData) {
                        var row = $('<tr>');
                        
                        if (ipData.marked_safe) {
                            row.addClass('info');
                        }
                        
                        // IP Address with connection info button - LEFT POSITIONED
                        var ipCell = $('<td>');
                        var connectionDetails = ipData.connection_details || '';
                        var connectionButton = createConnectionInfoButton(ipData.ip, connectionDetails);
                        var ipContent = connectionButton + ' ' + ipData.ip; // BUTTON FIRST
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
                    
                    $('.test-ip-btn').click(function() {
                        var ip = $(this).data('ip');
                        $("#ipToTest").val(ip);
                        $('a[href="#testip"]').tab('show');
                        $("#testIpBtn").click();
                    });
                    
                    bindConnectionInfoButtons();
                    
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
            $("#all-scanned-ips-info").removeClass("alert-info alert-success")
                .addClass("alert-danger")
                .text("{{ lang._('Failed to communicate with server') }}")
                .show();
        });
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
</script>