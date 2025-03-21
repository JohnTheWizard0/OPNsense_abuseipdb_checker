{#
    # Copyright (C) 2023 Your Name
    # All rights reserved.
    #
    # Redistribution and use in source and binary forms, with or without
    # modification, are permitted provided that the following conditions are met:
    #
    # 1. Redistributions of source code must retain the above copyright notice,
    #    this list of conditions and the following disclaimer.
    #
    # 2. Redistributions in binary form must reproduce the above copyright
    #    notice, this list of conditions and the following disclaimer in the
    #    documentation and/or other materials provided with the distribution.
    #
    # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    # POSSIBILITY OF SUCH DAMAGE.
    #}
   
   <script>
       $(document).ready(function() {
           // Load settings into form
           mapDataToFormUI({'frm_GeneralSettings':"/api/abuseipdbchecker/settings/get"}).done(function(data){
               formatTokenizersUI();
               $('.selectpicker').selectpicker('refresh');
           });
   
           // Link save button to API set action
           $("#saveAct").click(function(){
               saveFormToEndpoint("/api/abuseipdbchecker/settings/set", 'frm_GeneralSettings', function(){
                   // Action to run after successful save, reconfigure service
                   ajaxCall(url="/api/abuseipdbchecker/service/reload", sendData={}, callback=function(data,status) {
                       // Action to run after reload
                       loadStats();
                   });
               });
           });
   
           // Initialize database
           $("#initdbAct").SimpleActionButton({
               onPreAction: function() {
                   $("#initdbAct_progress").removeClass("hide");
                   return true;
               },
               onAction: function(data) {
                   if (data.status && data.status === 'ok') {
                       return "Database initialized successfully.";
                   } else {
                       return "Error initializing database: " + data.message;
                   }
               },
               onPostAction: function(data) {
                   $("#initdbAct_progress").addClass("hide");
               }
           });
   
           // Manual check
           $("#checkAct").SimpleActionButton({
               onPreAction: function() {
                   $("#checkAct_progress").removeClass("hide");
                   return true;
               },
               onAction: function(data) {
                   if (data.status && data.status === 'ok') {
                       loadStats();
                       loadThreats();
                       return "Manual check completed successfully.";
                   } else {
                       return "Error running manual check: " + data.message;
                   }
               },
               onPostAction: function(data) {
                   $("#checkAct_progress").addClass("hide");
               }
           });
   
           // Load statistics and threats on page load
           loadStats();
           loadThreats();
   
           // Update statistics every 60 seconds
           setInterval(function() {
               loadStats();
               loadThreats();
           }, 60000);
       });
   
       function loadStats() {
           ajaxCall(url="/api/abuseipdbchecker/service/stats", sendData={}, callback=function(data, status) {
               if (data.status === "ok") {
                   $("#stat-total-ips").text(data.total_ips || "0");
                   $("#stat-total-threats").text(data.total_threats || "0");
                   $("#stat-last-check").text(data.last_check || "Never");
                   $("#stat-daily-checks").text(data.daily_checks || "0");
                   $("#stat-daily-limit").text(data.daily_limit || "0");
               }
           });
       }
   
       function loadThreats() {
           ajaxCall(url="/api/abuseipdbchecker/service/threats", sendData={}, callback=function(data, status) {
               if (data.status === "ok" && data.threats) {
                   var tbody = $("#recent-threats tbody");
                   tbody.empty();
                   
                   if (data.threats.length === 0) {
                       tbody.append('<tr><td colspan="5" class="text-center">No threats detected</td></tr>');
                   } else {
                       $.each(data.threats, function(idx, threat) {
                           var row = $("<tr></tr>");
                           row.append($("<td></td>").text(threat.ip));
                           row.append($("<td></td>").text(threat.score));
                           row.append($("<td></td>").text(threat.reports));
                           row.append($("<td></td>").text(threat.last_seen));
                           row.append($("<td></td>").html('<a href="https://www.abuseipdb.com/check/' + threat.ip + '" target="_blank" class="btn btn-xs btn-default"><i class="fa fa-external-link"></i></a>'));
                           tbody.append(row);
                       });
                   }
               }
           });
       }
   </script>
   
   <div class="alert alert-info hidden" role="alert" id="responseMsg"></div>
   
   <ul class="nav nav-tabs" role="tablist" id="maintabs">
       <li class="active"><a data-toggle="tab" href="#settings"><b>{{ lang._('Settings') }}</b></a></li>
       <li><a data-toggle="tab" href="#statistics"><b>{{ lang._('Statistics') }}</b></a></li>
       <li><a data-toggle="tab" href="#threats"><b>{{ lang._('Recent Threats') }}</b></a></li>
   </ul>
   
   <div class="tab-content content-box">
       <div id="settings" class="tab-pane fade in active">
           {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_GeneralSettings']) }}
           
           <div class="col-md-12">
               <button class="btn btn-primary" id="saveAct" type="button"><b>{{ lang._('Save') }}</b></button>
               <button class="btn btn-default" id="initdbAct" data-endpoint="/api/abuseipdbchecker/service/initdb" data-label="{{ lang._('Initialize Database') }}"></button>
               <button class="btn btn-default" id="checkAct" data-endpoint="/api/abuseipdbchecker/service/check" data-label="{{ lang._('Run Manual Check') }}"></button>
               <div class="pull-right">
                   <span id="initdbAct_progress" class="hide">
                       <i class="fa fa-spinner fa-pulse"></i> {{ lang._('Initializing database...') }}
                   </span>
                   <span id="checkAct_progress" class="hide">
                       <i class="fa fa-spinner fa-pulse"></i> {{ lang._('Running check...') }}
                   </span>
               </div>
           </div>
       </div>
       
       <div id="statistics" class="tab-pane fade">
           <div class="content-box">
               <div class="col-sm-12">
                   <h2>{{ lang._('System Statistics') }}</h2>
                   <div class="row">
                       <div class="col-xs-6 col-sm-3">
                           <div class="panel panel-default">
                               <div class="panel-heading">
                                   <h3 class="panel-title">{{ lang._('Total IPs Checked') }}</h3>
                               </div>
                               <div class="panel-body">
                                   <h4 id="stat-total-ips">0</h4>
                               </div>
                           </div>
                       </div>
                       <div class="col-xs-6 col-sm-3">
                           <div class="panel panel-default">
                               <div class="panel-heading">
                                   <h3 class="panel-title">{{ lang._('Threats Detected') }}</h3>
                               </div>
                               <div class="panel-body">
                                   <h4 id="stat-total-threats">0</h4>
                               </div>
                           </div>
                       </div>
                       <div class="col-xs-6 col-sm-3">
                           <div class="panel panel-default">
                               <div class="panel-heading">
                                   <h3 class="panel-title">{{ lang._('Last Check') }}</h3>
                               </div>
                               <div class="panel-body">
                                   <h4 id="stat-last-check">Never</h4>
                               </div>
                           </div>
                       </div>
                       <div class="col-xs-6 col-sm-3">
                           <div class="panel panel-default">
                               <div class="panel-heading">
                                   <h3 class="panel-title">{{ lang._('API Usage') }}</h3>
                               </div>
                               <div class="panel-body">
                                   <h4><span id="stat-daily-checks">0</span> / <span id="stat-daily-limit">0</span></h4>
                               </div>
                           </div>
                       </div>
                   </div>
               </div>
           </div>
       </div>
       
       <div id="threats" class="tab-pane fade">
           <div class="content-box">
               <div class="col-sm-12">
                   <h2>{{ lang._('Recently Detected Threats') }}</h2>
                   <table id="recent-threats" class="table table-striped table-bordered">
                       <thead>
                           <tr>
                               <th>{{ lang._('IP Address') }}</th>
                               <th>{{ lang._('Abuse Score') }}</th>
                               <th>{{ lang._('Reports') }}</th>
                               <th>{{ lang._('Last Seen') }}</th>
                               <th>{{ lang._('Actions') }}</th>
                           </tr>
                       </thead>
                       <tbody>
                           <tr>
                               <td colspan="5" class="text-center">{{ lang._('Loading...') }}</td>
                           </tr>
                       </tbody>
                   </table>
               </div>
           </div>
       </div>
   </div>