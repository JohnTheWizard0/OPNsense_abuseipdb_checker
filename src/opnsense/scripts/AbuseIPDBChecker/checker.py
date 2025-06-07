#!/usr/local/bin/python3

"""
AbuseIPDB Checker - Main Orchestrator
Compartmentalized version with modular architecture for easier debugging and maintenance
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
    """Main orchestrator class for all AbuseIPDB operations"""
    
    def __init__(self):
        # Initialize managers
        self.config_manager = ConfigManager()
        self.db_manager = DatabaseManager()
        self.stats_manager = StatisticsManager(self.db_manager)
        self.daemon_manager = DaemonManager(self.config_manager, self.db_manager)
        
        # Get current configuration
        self.config = self.config_manager.get_config()
    
    def run_check(self):
        """Run manual IP check from firewall logs"""
        
        log_message("Starting manual IP check operation")

        validation = self.config_manager.validate_config()
        if validation['errors']:
            return {'status': 'error', 'message': f"Configuration errors: {', '.join(validation['errors'])}"}
        
        try:
            # Parse firewall logs for external IPs
            parser = FirewallLogParser(self.config)
            external_ips = parser.parse_log_for_ips()
            
            if not external_ips:
                self.db_manager.update_stat('last_check', get_db_timestamp())
                return {'status': 'ok', 'message': 'No external IPs found to check'}
            
            # Check daily limits
            daily_checks = int(self.db_manager.get_stat('daily_checks', '0'))
            daily_limit = self.config['daily_check_limit']
            
            if daily_checks >= daily_limit:
                return {'status': 'limited', 'message': f'Daily API check limit reached ({daily_checks}/{daily_limit})'}
            
            # Initialize API client and process IPs
            api_client = AbuseIPDBClient(self.config)
            result = self._process_manual_check(external_ips, api_client)
            
            log_message(f"Manual check completed: {result['ips_checked']} checked, {result['threats_detected']} threats")
            return result
            
        except Exception as e:
            error_msg = f'Error during manual check: {str(e)}'
            log_message(error_msg)
            return {'status': 'error', 'message': error_msg}
    
    def _process_manual_check(self, external_ips, api_client):
        """Process IPs for manual check"""
        threats_detected = 0
        ips_checked = 0
        
        daily_checks = int(self.db_manager.get_stat('daily_checks', '0'))
        daily_limit = self.config['daily_check_limit']
        
        for ip in external_ips:
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
                    result = self._process_ip_result(ip, report)
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
            
            # Process and store result
            result = self._process_ip_result(ip_address, report)
            
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
                "threat_level": result['threat_level'],
                "threat_text": result['threat_text'],
                "abuse_score": result['abuse_score'],
                "country": str(report.get("countryCode", "Unknown")),
                "isp": str(report.get("isp", "Unknown")),
                "domain": str(report.get("domain", "Unknown")),
                "reports": report.get("totalReports", 0),
                "last_reported": str(report.get("lastReportedAt", "Never")),
                "last_checked": format_timestamp()
            }
            
            log_message(f"Test completed for {ip_address}: {result['threat_text']} (Score: {result['abuse_score']})")
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
    
    def get_recent_threats(self):
        """Get recent threats"""
        return self.stats_manager.get_recent_threats()
    
    def get_all_checked_ips(self):
        """Get all checked IPs"""
        return self.stats_manager.get_all_checked_ips()
    
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
    
    def debug_log_parsing(self):
        """Debug firewall log parsing"""
        try:
            parser = FirewallLogParser(self.config)
            return parser.debug_log_parsing()
        except Exception as e:
            return {'status': 'error', 'message': f'Debug error: {str(e)}'}
    
    def list_connections(self):
        """List external→internal connections"""
        try:
            parser = FirewallLogParser(self.config)
            return parser.list_external_to_internal_connections()
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

def main():
    """Main entry point with compartmentalized architecture"""
    startup_message = "AbuseIPDBChecker compartmentalized script startup"
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {startup_message}", file=sys.stderr)
    system_log(startup_message)
    
    try:
        # Ensure directories exist
        ensure_directories()
        log_message("Compartmentalized script started successfully")
        
        # Parse arguments
        parser = argparse.ArgumentParser(description='AbuseIPDB Checker - Compartmentalized')
        parser.add_argument('mode', choices=[
            'check', 'stats', 'threats', 'logs', 'testip', 'listips', 'debuglog', 
            'connections', 'daemon', 'batchstatus', 'allips', 'exportthreats',
            'createalias', 'updatealias'
        ], help='Operation mode')
        parser.add_argument('ip', nargs='?', help='IP address to test (only for testip mode)')
        
        if len(sys.argv) < 2:
            parser.print_help()
            log_message("Error: No operation mode specified")
            print(json.dumps({'status': 'error', 'message': 'No operation mode specified'}))
            return
        
        # Filter configd %s parameters
        filtered_args = [arg for arg in sys.argv[1:] if arg != '%s']
        args = parser.parse_args(filtered_args)
        
        log_message(f"Running in {args.mode} mode")
        
        # Initialize checker
        checker = AbuseIPDBChecker()
        
        # Route to appropriate method
        if args.mode == 'check':
            result = checker.run_check()
        elif args.mode == 'stats':
            result = checker.get_statistics()
        elif args.mode == 'threats':
            result = checker.get_recent_threats()
        elif args.mode == 'logs':
            result = checker.get_logs()
        elif args.mode == 'testip':
            if not args.ip:
                result = {'status': 'error', 'message': 'IP address is required for testip mode'}
            else:
                result = checker.test_single_ip(args.ip)
        elif args.mode == 'listips':
            result = checker.list_external_ips()
        elif args.mode == 'debuglog':
            result = checker.debug_log_parsing()
        elif args.mode == 'connections':
            result = checker.list_connections()
        elif args.mode == 'batchstatus':
            result = checker.get_batch_status()
        elif args.mode == 'allips':
            result = checker.get_all_checked_ips()
        elif args.mode == 'exportthreats':
            result = checker.export_threats()
        elif args.mode == 'createalias':
            result = checker.create_malicious_ips_alias()
        elif args.mode == 'updatealias':
            result = checker.update_malicious_ips_alias()
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