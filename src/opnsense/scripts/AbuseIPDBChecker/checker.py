#!/usr/local/bin/python3

"""
AbuseIPDB Checker - Enhanced Main Orchestrator
With IP management, pagination, search, and port tracking features
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime

# Add lib directory to Python path
lib_path = os.path.join(os.path.dirname(__file__), 'lib')
sys.path.insert(0, lib_path)

try:
    from lib import (
        log_message, 
        system_log, 
        ensure_directories,
        log_timezone_info,
        format_timestamp,
        get_db_timestamp,
        classify_threat_level,
        get_threat_level_text,
        ConfigManager,
        DatabaseManager,
        AbuseIPDBClient,
        FirewallLogParser,
        StatisticsManager,
        DaemonManager
    )
    from lib.api_client import APIAuthenticationError, APIRateLimitError
except ImportError as e:
    print(f"Error importing modules: {str(e)}", file=sys.stderr)
    print(f'{{"status": "error", "message": "Missing required modules: {str(e)}"}}')
    sys.exit(1)

class AbuseIPDBChecker:
    """Enhanced main orchestrator class for all AbuseIPDB operations"""
    
    def __init__(self):
        # Initialize managers
        self.config_manager = ConfigManager()
        self.db_manager = DatabaseManager()
        self.stats_manager = StatisticsManager(self.db_manager)
        self.daemon_manager = DaemonManager(self.config_manager, self.db_manager)
        
        # Get current configuration
        self.config = self.config_manager.get_config()
    
    def run_check(self):
        """Run manual IP check from firewall logs with port extraction"""
        log_message("Starting manual IP check operation")

        validation = self.config_manager.validate_config()
        if validation['errors']:
            return {'status': 'error', 'message': f"Configuration errors: {', '.join(validation['errors'])}"}
        
        try:
            # Parse firewall logs for external IPs with ports
            parser = FirewallLogParser(self.config)
            external_connections = parser.parse_log_for_ips_with_connections()
            
            if not external_connections:
                self.db_manager.update_stat('last_check', get_db_timestamp())
                return {'status': 'ok', 'message': 'No external IPs found to check'}
            
            # Check daily limits
            daily_checks = int(self.db_manager.get_stat('daily_checks', '0'))
            daily_limit = self.config['daily_check_limit']
            
            if daily_checks >= daily_limit:
                return {'status': 'limited', 'message': f'Daily API check limit reached ({daily_checks}/{daily_limit})'}
            
            # Initialize API client and process IPs
            api_client = AbuseIPDBClient(self.config)
            result = self._process_manual_check_with_connections(external_connections, api_client)
            
            log_message(f"Manual check completed: {result['ips_checked']} checked, {result['threats_detected']} threats")
            return result
            
        except Exception as e:
            error_msg = f'Error during manual check: {str(e)}'
            log_message(error_msg)
            return {'status': 'error', 'message': error_msg}

    def _process_manual_check_with_connections(self, external_connections, api_client):
        """Process IPs for manual check with connection information"""
        threats_detected = 0
        ips_checked = 0
        
        daily_checks = int(self.db_manager.get_stat('daily_checks', '0'))
        daily_limit = self.config['daily_check_limit']
        
        for ip, connections in external_connections.items():
            if daily_checks >= daily_limit:
                break
            
            # Check if IP needs to be checked
            existing = self.db_manager.get_checked_ip(ip)
            if existing and self._is_recent_check(existing):
                continue
            
            try:
                # Check against API
                report = api_client.check_ip(ip)
                if report:
                    connection_strings = list(connections) if isinstance(connections, set) else connections
                    connection_details = '|'.join(connection_strings[:10])  # Limit to 10 connections
                    
                    result = self._process_ip_result_with_connections(ip, report, connection_details)
                    if result['is_threat']:
                        threats_detected += 1
                    ips_checked += 1
                    daily_checks += 1
                    
            except Exception as e:
                log_message(f"Error checking IP {ip}: {str(e)}")
                continue
        
        # Update statistics
        self.db_manager.update_stat('last_check', get_db_timestamp())
        self.db_manager.update_stat('daily_checks', str(daily_checks))
        
        total_checks = int(self.db_manager.get_stat('total_checks', '0'))
        self.db_manager.update_stat('total_checks', str(total_checks + ips_checked))
        
        return {
            'status': 'ok',
            'message': f'Check completed. Checked {ips_checked} IPs, detected {threats_detected} threats.',
            'ips_checked': ips_checked,
            'threats_detected': threats_detected
        }

    def _process_ip_result_with_connections(self, ip, report, connection_details):
        """Process API result and update database with connection information"""
        abuse_score = report.get('abuseConfidenceScore', 0)
        threat_level = classify_threat_level(abuse_score, self.config)
        country = report.get('countryCode', 'Unknown')
        
        # Update checked_ips table with connection info
        self.db_manager.update_checked_ip(ip, threat_level, country, connection_details)
        
        # Handle threats
        is_threat = False
        if threat_level >= 1:  # Suspicious or Malicious
            categories = self._extract_categories(report)
            self.db_manager.update_threat(ip, abuse_score, report.get('totalReports', 0), categories, country)
            is_threat = True
        else:
            self.db_manager.remove_threat(ip)
        
        return {
            'threat_level': threat_level,
            'threat_text': get_threat_level_text(threat_level),
            'abuse_score': abuse_score,
            'is_threat': is_threat
        }

    def remove_ip_from_threats(self, ip_address):
        """Remove IP from threats table completely"""
        log_message(f"Request to remove IP from threats: {ip_address}")
        
        try:
            # Validate IP format
            import ipaddress
            ipaddress.ip_address(ip_address)
            
            # Remove from threats table
            removed = self.db_manager.remove_threat(ip_address)
            
            if removed:
                log_message(f"Successfully removed {ip_address} from threats table")
                return {
                    'status': 'ok',
                    'message': f'IP {ip_address} removed from threats table',
                    'ip': ip_address,
                    'action': 'removed'
                }
            else:
                return {
                    'status': 'not_found',
                    'message': f'IP {ip_address} was not found in threats table',
                    'ip': ip_address
                }
                
        except ValueError:
            return {'status': 'error', 'message': f'Invalid IP address format: {ip_address}'}
        except Exception as e:
            error_msg = f"Error removing IP {ip_address}: {str(e)}"
            log_message(error_msg)
            return {'status': 'error', 'message': error_msg}
    
    def mark_ip_safe(self, ip_address, marked_by='admin'):
        """Mark IP as safe (keeps in threats table but marked as safe)"""
        log_message(f"Request to mark IP as safe: {ip_address} by {marked_by}")
        
        try:
            # Validate IP format
            import ipaddress
            ipaddress.ip_address(ip_address)
            
            # Mark as safe in threats table
            marked = self.db_manager.mark_ip_safe(ip_address, marked_by)
            
            if marked:
                log_message(f"Successfully marked {ip_address} as safe by {marked_by}")
                return {
                    'status': 'ok',
                    'message': f'IP {ip_address} marked as safe',
                    'ip': ip_address,
                    'marked_by': marked_by,
                    'action': 'marked_safe'
                }
            else:
                return {
                    'status': 'not_found',
                    'message': f'IP {ip_address} was not found in threats table',
                    'ip': ip_address
                }
                
        except ValueError:
            return {'status': 'error', 'message': f'Invalid IP address format: {ip_address}'}
        except Exception as e:
            error_msg = f"Error marking IP {ip_address} as safe: {str(e)}"
            log_message(error_msg)
            return {'status': 'error', 'message': error_msg}
    
    def unmark_ip_safe(self, ip_address):
        """Unmark IP as safe (restore threat status)"""
        log_message(f"Request to unmark IP as safe: {ip_address}")
        
        try:
            # Validate IP format
            import ipaddress
            ipaddress.ip_address(ip_address)
            
            # Unmark as safe in threats table
            unmarked = self.db_manager.unmark_ip_safe(ip_address)
            
            if unmarked:
                log_message(f"Successfully unmarked {ip_address} as safe - restored threat status")
                return {
                    'status': 'ok',
                    'message': f'IP {ip_address} unmarked as safe - threat status restored',
                    'ip': ip_address,
                    'action': 'unmarked_safe'
                }
            else:
                return {
                    'status': 'not_found',
                    'message': f'IP {ip_address} was not found in threats table',
                    'ip': ip_address
                }
                
        except ValueError:
            return {'status': 'error', 'message': f'Invalid IP address format: {ip_address}'}
        except Exception as e:
            error_msg = f"Error unmarking IP {ip_address} as safe: {str(e)}"
            log_message(error_msg)
            return {'status': 'error', 'message': error_msg}

    def get_recent_threats(self, limit=20, offset=0, search_ip='', include_marked_safe=True):
        """Get recent threats - CLEANED UP, no more sqlite3.Row conversion"""
        try:
            result = self.db_manager.get_recent_threats(limit, offset, search_ip, include_marked_safe)
            
            # Database layer now returns proper dictionaries, just pass through with formatting
            formatted_threats = []
            for threat_data in result['threats']:
                # Add any additional formatting here if needed
                threat_data['threat_level'] = classify_threat_level(threat_data['abuse_score'], self.config)
                formatted_threats.append(threat_data)
            
            return {
                'status': 'ok',
                'threats': formatted_threats,
                'total_count': result.get('total_count', 0),
                'limit': limit,
                'offset': offset
            }
            
        except Exception as e:
            log_message(f"Error retrieving recent threats: {str(e)}")
            import traceback
            log_message(f"Full traceback: {traceback.format_exc()}")
            return {
                'status': 'error', 
                'message': f'Error retrieving threats: {str(e)}',
                'threats': [],
                'total_count': 0,
                'limit': limit,
                'offset': offset
            }

    def get_all_checked_ips(self, limit=20, offset=0, search_ip=''):
        """Get all checked IPs - CLEANED UP, no more sqlite3.Row conversion"""
        try:
            result = self.db_manager.get_all_checked_ips(limit, offset, search_ip)
            
            # Database layer now returns proper dictionaries, just add threat text
            formatted_ips = []
            for ip_data in result['ips']:
                # Add threat level text
                ip_data['threat_text'] = get_threat_level_text(ip_data['threat_level'])
                formatted_ips.append(ip_data)
            
            return {
                'status': 'ok',
                'ips': formatted_ips,
                'total_count': result.get('total_count', 0),
                'limit': limit,
                'offset': offset
            }
            
        except Exception as e:
            log_message(f"Error retrieving all checked IPs: {str(e)}")
            import traceback
            log_message(f"Full traceback: {traceback.format_exc()}")
            return {
                'status': 'error', 
                'message': f'Error retrieving checked IPs: {str(e)}',
                'ips': [],
                'total_count': 0,
                'limit': limit,
                'offset': offset
            }
  
    def validate_configuration(self):
        """Validate configuration for service startup"""
        try:
            validation = self.config_manager.validate_config()
            
            # Enhanced validation for service startup
            config = self.config_manager.get_config()
            
            # Check critical requirements
            critical_errors = []
            warnings = []
            
            # API key validation
            if not config.get('api_key') or config['api_key'] == 'YOUR_API_KEY':
                critical_errors.append('AbuseIPDB API key is required')
            
            # Threshold validation
            if config['suspicious_threshold'] >= config['malicious_threshold']:
                critical_errors.append('Suspicious threshold must be less than malicious threshold')
            
            # Daily limit validation
            if config['daily_check_limit'] < 1 or config['daily_check_limit'] > 1000:
                critical_errors.append('Daily check limit must be between 1 and 1000')
            
            # Log file validation
            if not os.path.exists(config['log_file']):
                warnings.append(f"Log file not found: {config['log_file']}")
            
            # Database validation
            if not os.path.exists('/var/db/abuseipdbchecker/abuseipdb.db'):
                warnings.append('Database not initialized - will be created on first run')
            
            # OPNsense API validation (for alias features)
            if config['alias_enabled']:
                if not config.get('opnsense_api_key') or not config.get('opnsense_api_secret'):
                    warnings.append('OPNsense API credentials missing - alias management will be disabled')
            
            # Combine all validation results
            all_errors = validation.get('errors', []) + critical_errors
            all_warnings = validation.get('warnings', []) + warnings
            
            if all_errors:
                return {
                    'status': 'error',
                    'message': f'Configuration validation failed: {", ".join(all_errors)}',
                    'errors': all_errors,
                    'warnings': all_warnings
                }
            elif all_warnings:
                return {
                    'status': 'warning',
                    'message': f'Configuration has warnings but is usable: {", ".join(all_warnings)}',
                    'errors': [],
                    'warnings': all_warnings
                }
            else:
                return {
                    'status': 'ok',
                    'message': 'Configuration is valid and ready for service startup',
                    'errors': [],
                    'warnings': []
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Validation error: {str(e)}',
                'errors': [str(e)],
                'warnings': []
            }

    def test_single_ip(self, ip_address):
        """Test a single IP address against AbuseIPDB"""
        log_message(f"Starting test of IP: {ip_address}")
        
        # Validate IP format
        import ipaddress
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return {'status': 'error', 'message': f'Invalid IP address format: {ip_address}'}
        
        # Check service status
        validation = self.config_manager.validate_config()
        if validation['errors']:
            return {'status': 'error', 'message': f"Configuration errors: {', '.join(validation['errors'])}"}
        
        if not self.config['api_key'] or self.config['api_key'] == 'YOUR_API_KEY':
            return {'status': 'error', 'message': 'Please configure a valid API key in the API settings'}
        
        try:
            # Initialize API client and test
            api_client = AbuseIPDBClient(self.config)
            report = api_client.check_ip(ip_address)
            
            if not report:
                return {'status': 'error', 'message': 'No response from AbuseIPDB API'}
            
            # Process and store result with proper port handling
            abuse_score = report.get('abuseConfidenceScore', 0)
            threat_level = classify_threat_level(abuse_score, self.config)
            country = report.get('countryCode', 'Unknown')
            
            # For manual IP tests, we don't have port info, so pass empty string
            self.db_manager.update_checked_ip(ip_address, threat_level, country, '')
            
            # Handle threats
            is_threat = False
            if threat_level >= 1:  # Suspicious or Malicious
                categories = self._extract_categories(report)
                self.db_manager.update_threat(ip_address, abuse_score, report.get('totalReports', 0), categories, country)
                is_threat = True
            else:
                self.db_manager.remove_threat(ip_address)

            if is_threat and self.config.get('ntfy_enabled', False):
                try:
                    from lib.ntfy_client import NtfyClient
                    ntfy_client = NtfyClient(self.config)
                    
                    ntfy_result = ntfy_client.send_threat_notification(
                        ip_address=ip_address,
                        abuse_score=abuse_score,
                        threat_level=threat_level,
                        country=country,
                        connection_details='',  # No connection details for manual tests
                        is_new_threat=True
                    )
                    
                    if ntfy_result['status'] == 'success':
                        log_message(f"ntfy notification sent for manual test of {ip_address}")
                    elif ntfy_result['status'] != 'skipped':
                        log_message(f"ntfy notification failed for manual test: {ntfy_result['message']}")
                        
                except Exception as e:
                    log_message(f"Error sending ntfy notification for manual test: {str(e)}")
            
            # Update statistics
            daily_checks = int(self.db_manager.get_stat('daily_checks', '0'))
            self.db_manager.update_stat('daily_checks', str(daily_checks + 1))
            
            total_checks = int(self.db_manager.get_stat('total_checks', '0'))
            self.db_manager.update_stat('total_checks', str(total_checks + 1))
            
            self.db_manager.update_stat('last_check', get_db_timestamp())
            
            # Format response
            response = {
                "status": "ok",
                "ip": ip_address,
                "threat_level": threat_level,
                "threat_text": get_threat_level_text(threat_level),
                "abuse_score": abuse_score,
                "country": str(report.get("countryCode", "Unknown")),
                "isp": str(report.get("isp", "Unknown")),
                "domain": str(report.get("domain", "Unknown")),
                "reports": report.get("totalReports", 0),
                "last_reported": str(report.get("lastReportedAt", "Never")),
                "last_checked": format_timestamp(),
                "is_threat": is_threat
            }
            
            log_message(f"Test completed for {ip_address}: {get_threat_level_text(threat_level)} (Score: {abuse_score}%)")
            return response
            
        except APIAuthenticationError:
            return {'status': 'error', 'message': 'API authentication failed - check your API key'}
        except APIRateLimitError:
            return {'status': 'error', 'message': 'API rate limit exceeded - try again later'}
        except Exception as e:
            error_msg = f"Error processing request: {str(e)}"
            log_message(error_msg)
            return {"status": "error", "message": error_msg}
    
    def _process_ip_result(self, ip, report):
        """Process API result and update database"""
        abuse_score = report.get('abuseConfidenceScore', 0)
        threat_level = classify_threat_level(abuse_score, self.config)
        country = report.get('countryCode', 'Unknown')
        
        # Update checked_ips table
        self.db_manager.update_checked_ip(ip, threat_level, country)
        
        # Handle threats
        is_threat = False
        if threat_level >= 1:  # Suspicious or Malicious
            categories = self._extract_categories(report)
            self.db_manager.update_threat(ip, abuse_score, report.get('totalReports', 0), categories, country)
            is_threat = True
        else:
            self.db_manager.remove_threat(ip)
        
        return {
            'threat_level': threat_level,
            'threat_text': get_threat_level_text(threat_level),
            'abuse_score': abuse_score,
            'is_threat': is_threat
        }
    
    def _extract_categories(self, report):
        """Extract categories from API report"""
        categories = ''
        if 'reports' in report and report['reports'] and len(report['reports']) > 0:
            if 'categories' in report['reports'][0]:
                categories = ','.join(str(cat) for cat in report['reports'][0]['categories'])
        return categories
    
    def _is_recent_check(self, existing_record):
        """Check if IP was recently checked based on frequency setting"""
        from datetime import datetime, timedelta
        
        last_checked = datetime.strptime(existing_record['last_checked'], '%Y-%m-%d %H:%M:%S')
        cutoff = datetime.now() - timedelta(days=self.config['check_frequency'])
        return last_checked > cutoff
    
    def get_statistics(self):
        """Get comprehensive statistics"""
        return self.stats_manager.get_comprehensive_stats(self.config)
    
    def get_logs(self):
        """Get recent logs"""
        from lib.core_utils import LOG_FILE
        
        try:
            if not os.path.exists(LOG_FILE):
                return {'status': 'ok', 'logs': ['No log entries found.']}
            
            with open(LOG_FILE, 'r') as f:
                content = f.read()
                if not content.strip():
                    return {'status': 'ok', 'logs': ['No log entries found.']}
                
                # Filter out verbose debug messages
                lines = content.splitlines()
                verbose_patterns = [
                    'Running in', 'Retrieving', 'Operation completed with status: ok',
                    'Script started successfully', 'Configuration loaded', 'Poll completed successfully',
                    'sleeping for 5 seconds', 'Polling for external IPs', 'Would check these IPs',
                    'API calls disabled in daemon mode', 'continuing to poll', 'Database stats:',
                    'Found 0 external IPs', 'No external IPs found in current'
                ]
                
                filtered_lines = []
                for line in lines:
                    if not line.strip():
                        continue
                    
                    is_verbose = any(pattern.lower() in line.lower() for pattern in verbose_patterns)
                    if not is_verbose:
                        filtered_lines.append(line)
                
                # Get last 50 important lines (most recent first)
                important_lines = filtered_lines[-50:] if len(filtered_lines) > 50 else filtered_lines
                important_lines.reverse()
                
                if not important_lines:
                    return {'status': 'ok', 'logs': ['No important log entries found.']}
                
                return {'status': 'ok', 'logs': important_lines}
                
        except Exception as e:
            return {'status': 'error', 'message': f'Error retrieving logs: {str(e)}'}
    
    def list_external_ips(self):
        """List external IPs from firewall logs"""
        try:
            validation = self.config_manager.validate_config()
            if validation['errors']:
                return {
                    'status': 'error', 
                    'message': f"Configuration errors: {', '.join(validation['errors'])}"
                }
            
            parser = FirewallLogParser(self.config)
            external_ips = parser.parse_log_for_ips(recent_only=True)
            
            results = []
            for ip in sorted(list(external_ips)):
                db_record = self.db_manager.get_checked_ip(ip)
                
                ip_info = {
                    'ip': ip,
                    'checked': 'No',
                    'threat_status': 'Unknown',
                    'last_checked': 'Never'
                }
                
                if db_record:
                    ip_info['checked'] = 'Yes'
                    threat_level = db_record['threat_level'] or 0
                    threat_map = {0: 'Safe', 1: 'Suspicious', 2: 'Threat'}
                    ip_info['threat_status'] = threat_map.get(threat_level, 'Unknown')
                    ip_info['last_checked'] = db_record['last_checked']
                
                results.append(ip_info)
            
            return {
                'status': 'ok',
                'message': f'Found {len(results)} external IPs in recent logs',
                'ips': results,
                'total_count': len(results)
            }
            
        except Exception as e:
            return {'status': 'error', 'message': f'Error: {str(e)}'}
  
    def get_batch_status(self):
        """Get daemon batch processing status"""
        return self.daemon_manager.get_daemon_status()
    
    def export_threats(self):
        """Export threats data"""
        return self.stats_manager.export_threats_data()
    
    def create_malicious_ips_alias(self):
        """Create MaliciousIPs alias using configd action"""
        try:
            log_message("Creating alias via configd action")
            result = subprocess.run([
                'configctl', 'abuseipdbchecker', 'createalias'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                try:
                    response_data = json.loads(result.stdout)
                    log_message(f"Configd create result: {response_data}")
                    return response_data
                except json.JSONDecodeError:
                    return {'status': 'error', 'message': f'Invalid JSON response: {result.stdout}'}
            else:
                return {'status': 'error', 'message': f'Configd error: {result.stderr}'}
                
        except Exception as e:
            error_msg = f"Error creating alias via configd: {str(e)}"
            log_message(error_msg)
            return {'status': 'error', 'message': error_msg}
    
    def update_malicious_ips_alias(self):
        """Update MaliciousIPs alias using configd action"""
        try:
            if not self.config['alias_enabled']:
                return {'status': 'disabled', 'message': 'Alias integration is disabled'}
            
            log_message("Updating alias via configd action")
            result = subprocess.run([
                'configctl', 'abuseipdbchecker', 'updatealias'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                try:
                    response_data = json.loads(result.stdout)
                    log_message(f"Configd update result: {response_data}")
                    return response_data
                except json.JSONDecodeError:
                    return {'status': 'error', 'message': f'Invalid JSON response: {result.stdout}'}
            else:
                return {'status': 'error', 'message': f'Configd error: {result.stderr}'}
                
        except Exception as e:
            error_msg = f"Error updating alias via configd: {str(e)}"
            log_message(error_msg)
            return {'status': 'error', 'message': error_msg}
   
   
    def test_ntfy_configuration(self, server, topic, token='', priority='3'):
        """Test ntfy configuration with provided parameters"""
        log_message(f"Testing ntfy configuration: {server}/{topic}")
        
        try:
            # Validate and clean priority
            if not priority or priority == '':
                priority = '3'
            
            # Handle priority safely
            try:
                priority_int = int(priority)
                # Clamp to valid range
                priority_int = max(1, min(5, priority_int))
            except (ValueError, TypeError):
                priority_int = 3
            
            # Create temporary config for testing
            test_config = {
                'ntfy_enabled': True,
                'ntfy_server': server,
                'ntfy_topic': topic,
                'ntfy_token': token,
                'ntfy_priority': priority_int,
                'ntfy_notify_malicious': True,
                'ntfy_notify_suspicious': True,
                'ntfy_include_connection_details': True
            }
            
            # Import and initialize ntfy client with test config
            from lib.ntfy_client import NtfyClient
            ntfy_client = NtfyClient(test_config)
            
            # Send test notification
            result = ntfy_client.test_notification()
            
            log_message(f"ntfy test result: {result['status']}")
            return result
            
        except Exception as e:
            error_msg = f"ntfy test error: {str(e)}"
            log_message(error_msg)
            return {'status': 'error', 'message': error_msg}

def main():
    """Enhanced main entry point with new IP management commands"""
    startup_message = "AbuseIPDBChecker enhanced script startup"
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {startup_message}", file=sys.stderr)
    system_log(startup_message)
    
    try:
        # Ensure directories exist
        ensure_directories()
        log_message("Enhanced script started successfully")
        
        # Parse arguments
        parser = argparse.ArgumentParser(description='AbuseIPDB Checker - Enhanced')
        parser.add_argument('mode', choices=[
            'check', 'stats', 'threats', 'logs', 'testip', 'listips', 'daemon', 'batchstatus', 'allips', 'exportthreats',
            'createalias', 'updatealias', 'removeip', 'marksafe', 'unmarksafe', 'testntfy'
        ], help='Operation mode')
        parser.add_argument('args', nargs='*', help='Additional arguments based on mode')
        
        if len(sys.argv) < 2:
            parser.print_help()
            log_message("Error: No operation mode specified")
            print(json.dumps({'status': 'error', 'message': 'No operation mode specified'}))
            return
        
        # Filter configd %s parameters
        filtered_args = [arg for arg in sys.argv[1:] if arg != '%s']
        args = parser.parse_args(filtered_args)
        
        log_message(f"Running in {args.mode} mode with args: {args.args}")
        
        # Initialize checker
        checker = AbuseIPDBChecker()
        
        # Route to appropriate method
        if args.mode == 'check':
            result = checker.run_check()
        elif args.mode == 'stats':
            result = checker.get_statistics()
        elif args.mode == 'threats':
            # Parse pagination arguments: limit, offset, search, include_marked_safe
            limit = int(args.args[0]) if len(args.args) > 0 and args.args[0].isdigit() else 20
            offset = int(args.args[1]) if len(args.args) > 1 and args.args[1].isdigit() else 0
            search = args.args[2] if len(args.args) > 2 else ''
            include_marked_safe = args.args[3] == '1' if len(args.args) > 3 else True
            result = checker.get_recent_threats(limit, offset, search, include_marked_safe)
        elif args.mode == 'allips':
            # Parse pagination arguments: limit, offset, search
            limit = int(args.args[0]) if len(args.args) > 0 and args.args[0].isdigit() else 20
            offset = int(args.args[1]) if len(args.args) > 1 and args.args[1].isdigit() else 0
            search = args.args[2] if len(args.args) > 2 else ''
            result = checker.get_all_checked_ips(limit, offset, search)
        elif args.mode == 'testip':
            if not args.args:
                result = {'status': 'error', 'message': 'IP address is required for testip mode'}
            else:
                result = checker.test_single_ip(args.args[0])
        elif args.mode == 'removeip':
            if not args.args:
                result = {'status': 'error', 'message': 'IP address is required for removeip mode'}
            else:
                result = checker.remove_ip_from_threats(args.args[0])
        elif args.mode == 'marksafe':
            if not args.args:
                result = {'status': 'error', 'message': 'IP address is required for marksafe mode'}
            else:
                ip = args.args[0]
                marked_by = args.args[1] if len(args.args) > 1 else 'admin'
                result = checker.mark_ip_safe(ip, marked_by)
        elif args.mode == 'unmarksafe':
            if not args.args:
                result = {'status': 'error', 'message': 'IP address is required for unmarksafe mode'}
            else:
                result = checker.unmark_ip_safe(args.args[0])
        elif args.mode == 'logs':
            result = checker.get_logs()
        elif args.mode == 'listips':
            result = checker.list_external_ips()
        elif args.mode == 'batchstatus':
            result = checker.get_batch_status()
        elif args.mode == 'exportthreats':
            result = checker.export_threats()
        elif args.mode == 'createalias':
            result = checker.create_malicious_ips_alias()
        elif args.mode == 'updatealias':
            result = checker.update_malicious_ips_alias()
        elif args.mode == 'testntfy':
            if len(args.args) < 2:
                result = {'status': 'error', 'message': 'Server and topic are required for testntfy mode'}
            else:
                server = args.args[0]
                topic = args.args[1] 
                token = args.args[2] if len(args.args) > 2 else ''
                priority = args.args[3] if len(args.args) > 3 else '3'
                result = checker.test_ntfy_configuration(server, topic, token, priority)
        elif args.mode == 'daemon':
            log_message("Starting daemon mode")
            checker.daemon_manager.start_daemon()
            return
        else:
            result = {'status': 'error', 'message': f'Invalid mode: {args.mode}'}
        
        # Output result
        print(json.dumps(result, separators=(',', ':')))
        log_message(f"Operation completed with status: {result.get('status', 'unknown')}")
        
    except Exception as e:
        error_msg = f"Unhandled exception: {str(e)}"
        system_log(error_msg)
        
        try:
            log_message(error_msg)
        except:
            pass
        
        print(json.dumps({'status': 'error', 'message': error_msg}, separators=(',', ':')))
        print(error_msg, file=sys.stderr)

if __name__ == '__main__':
    main()