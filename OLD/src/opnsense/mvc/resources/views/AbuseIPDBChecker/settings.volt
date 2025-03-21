{#
    # AbuseIPDB Checker settings page
    #}
    
   {% extends "layout_partials/base_form.volt" %}
   
   {% block main_form %}
       <div class="content-box">
           <div class="content-box-main">
               <div class="table-responsive">
                   <table class="table table-striped">
                       <colgroup>
                           <col class="col-md-3"/>
                           <col class="col-md-9"/>
                       </colgroup>
                       <tbody>
                           <!-- General Settings -->
                           <tr>
                               <td colspan="2"><strong>{{ lang._('General Settings') }}</strong></td>
                           </tr>
                           <tr>
                               <td><a id="help_for_general.enabled" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Enable Plugin') }}</td>
                               <td>
                                   <input name="general.enabled" type="checkbox" value="1" {% if general.enabled|default('0') == '1' %}checked="checked"{% endif %}/>
                                   <div class="hidden" data-for="help_for_general.enabled">
                                       <small>{{ lang._('Enable or disable the AbuseIPDB Checker plugin.') }}</small>
                                   </div>
                               </td>
                           </tr>
                           <tr>
                               <td><a id="help_for_general.checkFrequency" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Check Frequency (days)') }}</td>
                               <td>
                                   <input name="general.checkFrequency" type="number" min="1" max="30" value="{{ general.checkFrequency|default('7') }}" class="form-control"/>
                                   <div class="hidden" data-for="help_for_general.checkFrequency">
                                       <small>{{ lang._('Number of days to wait before rechecking an IP address.') }}</small>
                                   </div>
                               </td>
                           </tr>
                           <tr>
                               <td><a id="help_for_general.abuseScoreThreshold" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Abuse Score Threshold') }}</td>
                               <td>
                                   <input name="general.abuseScoreThreshold" type="number" min="1" max="100" value="{{ general.abuseScoreThreshold|default('80') }}" class="form-control"/>
                                   <div class="hidden" data-for="help_for_general.abuseScoreThreshold">
                                       <small>{{ lang._('Minimum confidence score (1-100) to consider an IP a potential threat.') }}</small>
                                   </div>
                               </td>
                           </tr>
                           
                           <!-- API Settings -->
                           <tr>
                               <td colspan="2"><strong>{{ lang._('AbuseIPDB API Settings') }}</strong></td>
                           </tr>
                           <tr>
                               <td><a id="help_for_api.key" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('API Key') }}</td>
                               <td>
                                   <input name="api.key" type="text" value="{{ api.key|default('') }}" class="form-control"/>
                                   <div class="hidden" data-for="help_for_api.key">
                                       <small>{{ lang._('Your AbuseIPDB API key. Sign up at https://www.abuseipdb.com/ to get one.') }}</small>
                                   </div>
                               </td>
                           </tr>
                           <!-- Add this after the API Key section -->
                            <tr>
                                <td><a id="help_for_api.endpoint" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('API Endpoint') }}</td>
                                <td>
                                    <input name="api.endpoint" type="text" value="{{ api.endpoint|default('https://www.abuseipdb.com/check') }}" class="form-control"/>
                                    <div class="hidden" data-for="help_for_api.endpoint">
                                        <small>{{ lang._('AbuseIPDB API endpoint URL. Should not need to be changed unless the API changes.') }}</small>
                                    </div>
                                </td>
                            </tr>
                           <tr>
                               <td><a id="help_for_api.maxAge" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Max Age (days)') }}</td>
                               <td>
                                   <input name="api.maxAge" type="number" min="1" max="365" value="{{ api.maxAge|default('90') }}" class="form-control"/>
                                   <div class="hidden" data-for="help_for_api.maxAge">
                                       <small>{{ lang._('Maximum age in days for IP reports to consider.') }}</small>
                                   </div>
                               </td>
                           </tr>
                           
                           <!-- Email Settings -->
                           <tr>
                               <td colspan="2"><strong>{{ lang._('Email Notification Settings') }}</strong></td>
                           </tr>
                           <tr>
                               <td><a id="help_for_email.enabled" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('Enable Email Notifications') }}</td>
                               <td>
                                   <input name="email.enabled" type="checkbox" value="1" {% if email.enabled|default('1') == '1' %}checked="checked"{% endif %}/>
                                   <div class="hidden" data-for="help_for_email.enabled">
                                       <small>{{ lang._('Enable or disable email notifications for potential threats.') }}</small>
                                   </div>
                               </td>
                           </tr>
                           <tr>
                               <td><a id="help_for_email.smtpServer" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('SMTP Server') }}</td>
                               <td>
                                   <input name="email.smtpServer" type="text" value="{{ email.smtpServer|default('') }}" class="form-control"/>
                                   <div class="hidden" data-for="help_for_email.smtpServer">
                                       <small>{{ lang._('SMTP server address for sending email notifications.') }}</small>
                                   </div>
                               </td>
                           </tr>
                           <tr>
                               <td><a id="help_for_email.toAddress" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> {{ lang._('To Email Address') }}</td>
                               <td>
                                   <input name="email.toAddress" type="text" value="{{ email.toAddress|default('') }}" class="form-control"/>
                                   <div class="hidden" data-for="help_for_email.toAddress">
                                       <small>{{ lang._('Recipient email address for notifications.') }}</small>
                                   </div>
                               </td>
                           </tr>
                       </tbody>
                   </table>
               </div>
           </div>
       </div>
   {% endblock %}
   
   {% block footerjs %}
   <script>
       $(document).ready(function() {
           var data_get_map = {'frm_GeneralSettings':"/api/abuseipdbchecker/settings/get"};
           mapDataToFormUI(data_get_map).done(function(data){
               // place actions to run after load, for example update form styles
           });
   
           // link save button to API set action
           $("#saveAct").click(function(){
               saveFormToEndpoint(url="/api/abuseipdbchecker/settings/set",formid='frm_GeneralSettings',callback_ok=function(){
                   // action to run after successful save, for example reconfigure service
                   ajaxCall(url="/api/abuseipdbchecker/service/reconfigure", sendData={});
               });
           });
           
           $("#runNowAct").click(function() {
               // Disable button and show spinner
               $(this).prop('disabled', true);
               $(this).html('<i class="fa fa-spinner fa-spin"></i> {{ lang._("Running...) }}');
               
               // Call the API to run checker
               ajaxCall(
                   url="/api/abuseipdbchecker/settings/run",
                   sendData={},
                   callback=function(data,status){
                       // Re-enable button
                       $("#runNowAct").prop('disabled', false);
                       $("#runNowAct").html('<i class="fa fa-play"></i> {{ lang._("Run Now") }}');
                       
                       // Show result
                       if (data && data.result) {
                           BootstrapDialog.show({
                               type: BootstrapDialog.TYPE_INFO,
                               title: '{{ lang._("Results") }}',
                               message: data.result.replace(/\n/g, '<br>'),
                               buttons: [{
                                   label: '{{ lang._("Close") }}',
                                   action: function(dialogRef) {
                                       dialogRef.close();
                                   }
                               }]
                           });
                       }
                   }
               );
           });
       });
   </script>
   {% endblock %}