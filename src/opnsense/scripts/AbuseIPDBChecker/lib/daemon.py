#!/usr/local/bin/python3

"""
Enhanced Daemon Manager Module
Handles daemon operations, batch processing, and automated threat detection with port tracking
"""

import os
import sys
import time
import signal
import json
import subprocess
from datetime import datetime, timedelta
from .core_utils import log_message, classify_threat_level, get_threat_level_text
from .ntfy_client import NtfyClient

class DaemonManager:
    """Enhanced daemon operations with batch processing, alias updates, and port tracking"""
    
    def __init__(self, config_manager=None, db_manager=None):
        # Accept managers as dependencies to avoid circular imports
        self.config_manager = config_manager
        self.db_manager = db_manager
        self.running = False
        self.batch_interval = 15  # seconds
        self.poll_interval = 2.5  # seconds
        
    def start_daemon(self):
        """Start the daemon with signal handling and batch processing"""
        log_message(f"AbuseIPDB Checker daemon starting - PID: {os.getpid()}")
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        self.running = True
        self._run_daemon_loop()
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        log_message(f"Received signal {signum}, stopping daemon gracefully")
        self.running = False
        sys.exit(0)

    def _run_daemon_loop(self):
        """Main daemon loop with batch collection and processing including port tracking"""
        ip_connections = {}  # ip -> {ports: set, last_seen: timestamp}
        last_batch_time = time.time()
        poll_count = 0
        
        log_message(f"Daemon configured: batch_interval={self.batch_interval}s, poll_interval={self.poll_interval}s")
        
        while self.running:
            try:
                poll_count += 1
                current_time = time.time()
                
                # Reload configuration periodically
                if poll_count % 20 == 0:  # Every 50 seconds
                    self.config_manager.reload()
                
                config = self.config_manager.get_config()
                
                # Validate critical configuration before processing
                validation = self.config_manager.validate_config()
                if validation['errors']:
                    log_message(f"Configuration errors detected: {', '.join(validation['errors'])}")
                    log_message("Skipping processing until configuration is fixed")
                    time.sleep(self.poll_interval)
                    continue
                
                # Collect external IPs with port information from current logs
                new_connections = self._collect_external_connections(config)
                new_count = 0
                
                if new_connections:
                    for ip, ports in new_connections.items():
                        if ip not in ip_connections:
                            ip_connections[ip] = {'ports': set(), 'last_seen': current_time}
                            new_count += 1
                        
                        # Convert ports to set and check for new ports
                        new_ports_set = set(ports) if isinstance(ports, (list, tuple)) else ports
                        existing_ports = ip_connections[ip]['ports']
                        
                        # Find truly new ports
                        genuinely_new_ports = new_ports_set - existing_ports
                        
                        if genuinely_new_ports:
                            formatted_connections = self._format_connection_strings(genuinely_new_ports)
                            log_message(f"Poll #{poll_count}: IP {ip} | {formatted_connections}")
                        
                        # Add new ports and update last seen
                        ip_connections[ip]['ports'].update(new_ports_set)
                        ip_connections[ip]['last_seen'] = current_time
                
                if new_count > 0:
                    log_message(f"Poll #{poll_count}: Found {new_count} new external IPs")
                
                # Check if it's time to process the batch
                if current_time - last_batch_time >= self.batch_interval:
                    if ip_connections:
                        log_message(f"=== BATCH PROCESSING: {len(ip_connections)} unique IPs ===")
                        result = self._process_ip_batch_with_connections(ip_connections, config)
                        self._log_batch_result(result)
                        ip_connections.clear()
                    else:
                        log_message("=== BATCH PROCESSING: No IPs to process ===")
                    
                    last_batch_time = current_time
                
                # Sleep until next poll
                time.sleep(self.poll_interval)
                
            except KeyboardInterrupt:
                log_message("Received keyboard interrupt, stopping daemon")
                break
            except Exception as e:
                log_message(f"Error in daemon loop: {str(e)}")
                time.sleep(self.poll_interval)
        
        log_message("AbuseIPDB Checker daemon shutting down")

    def _format_connection_strings(self, connection_strings):
        """Format connection strings efficiently"""
        if not connection_strings:
            return ""
        
        # Limit to 3 connections for logging efficiency 
        limited = list(connection_strings)[:3]
        formatted = []
        
        for conn_str in limited:
            if '->' in conn_str:
                source_part, dest_part = conn_str.split(' -> ', 1)
                source_port = source_part.split(':')[-1] if ':' in source_part else 'unknown'
                formatted.append(f"Port {source_port} accessing {dest_part}")
            else:
                formatted.append(f"Connection: {conn_str}")
        
        result = ', '.join(formatted)
        if len(connection_strings) > 3:
            result += f" (+{len(connection_strings)-3} more)"
        
        return result

    def _collect_external_connections(self, config):
        """Collect external IPs with full connection details from firewall logs"""
        try:
            # Import locally to avoid circular imports
            from .log_parser import FirewallLogParser
            parser = FirewallLogParser(config)
            return parser.parse_log_for_ips_with_connections(recent_only=True)
        except Exception as e:
            log_message(f"Error collecting connections: {str(e)}")
            return {}

    def _process_ip_batch_with_connections(self, ip_connections, config):
        """Process a batch of collected IPs with connection information"""
        if not ip_connections:
            return {'status': 'ok', 'ips_checked': 0, 'threats_detected': 0, 'skipped': 0}
        
        try:
            # Reset daily checks if needed
            self.db_manager.reset_daily_checks_if_needed()
            
            # Check daily limits
            daily_checks = int(self.db_manager.get_stat('daily_checks', '0'))
            daily_limit = config['daily_check_limit']
            
            if daily_checks >= daily_limit:
                return {
                    'status': 'limited',
                    'message': f'Daily API limit reached ({daily_checks}/{daily_limit})',
                    'ips_checked': 0, 'threats_detected': 0, 'skipped': len(ip_connections)
                }
            
            # Filter IPs that need checking
            ips_to_check = self._filter_ips_for_checking_with_connections(ip_connections, config)
            skipped_count = len(ip_connections) - len(ips_to_check)
            
            # Limit to daily quota
            available_checks = daily_limit - daily_checks
            if len(ips_to_check) > available_checks:
                original_to_check = ips_to_check.copy()
                ips_to_check = dict(list(ips_to_check.items())[:available_checks])
                skipped_count = len(ip_connections) - len(ips_to_check)
            
            log_message(f"Enhanced batch filter: {len(ips_to_check)} to check, {skipped_count} skipped")
            
            # Process each IP with connection information
            result = self._check_ips_with_api_and_connections(ips_to_check, config)
            result['skipped'] = skipped_count
            
            # Update statistics
            self._update_batch_stats(result)
            
            # Auto-update alias ONLY if NEW threats detected
            if result.get('new_threats_detected', 0) > 0:
                self._auto_update_alias(config, result['new_threats_detected'])
            
            return result
        
        except Exception as e:
            log_message(f"Error in process_ip_batch_with_connections: {str(e)}")
            return {'status': 'error', 'message': f'Enhanced batch processing error: {str(e)}'}

    def _filter_ips_for_checking_with_connections(self, ip_connections, config):
        """Filter IPs that need to be checked based on frequency, keeping connection info"""
        ips_to_check = {}
        
        for ip, connections in ip_connections.items():
            existing = self.db_manager.get_checked_ip(ip)
            
            if existing:
                last_checked = datetime.strptime(existing['last_checked'], '%Y-%m-%d %H:%M:%S')
                if last_checked > (datetime.now() - timedelta(days=config['check_frequency'])):
                    continue
            
            ips_to_check[ip] = connections
        
        return ips_to_check

    def _check_ips_with_api_and_connections(self, ips_to_check, config):
        """Check IPs against AbuseIPDB API with connection information tracking"""
        # Import locally to avoid circular imports
        from .api_client import AbuseIPDBClient
        
        api_client = AbuseIPDBClient(config)
        threats_detected = 0
        new_threats_detected = 0  # Track NEW threats only
        ips_checked = 0
        
        for ip, connections in ips_to_check.items():
            try:
                # FIX: Properly handle different connection data types
                if isinstance(connections, set):
                    connection_strings = list(connections)
                elif isinstance(connections, (list, tuple)):
                    connection_strings = list(connections)
                elif isinstance(connections, str):
                    connection_strings = [connections]
                else:
                    # Handle any other type - convert to string first
                    try:
                        connection_strings = [str(connections)]
                    except Exception as e:
                        log_message(f"Warning: Could not convert connections for {ip}: {str(e)}")
                        connection_strings = []
                
                # FIX: Ensure we only work with strings and avoid slice objects
                safe_connection_strings = []
                for conn in connection_strings:
                    try:
                        # Ensure each connection is a string
                        if isinstance(conn, str):
                            safe_connection_strings.append(conn)
                        else:
                            safe_connection_strings.append(str(conn))
                    except Exception as e:
                        log_message(f"Warning: Skipping invalid connection for {ip}: {str(e)}")
                        continue
                
                # Limit to 10 connections safely
                limited_connections = safe_connection_strings[:10] if safe_connection_strings else []
                connection_details = '|'.join(limited_connections)
                
                log_message(f"Checking IP: {ip} (connections: {len(limited_connections)})")
                
                # Check if IP was previously a threat
                existing_threat = self.db_manager.get_threat(ip)
                was_threat = existing_threat is not None
                
                # Check against AbuseIPDB
                report = api_client.check_ip(ip)
                
                if report:
                    abuse_score = report.get('abuseConfidenceScore', 0)
                    threat_level = classify_threat_level(abuse_score, config)
                    country = report.get('countryCode', 'Unknown')
                    
                    # Update database with connection information
                    self.db_manager.update_checked_ip(ip, threat_level, country, connection_details)
                    
                    # Handle threats
                    if threat_level >= 1:  # Suspicious or Malicious
                        categories = self._extract_categories(report)
                        self.db_manager.update_threat(ip, abuse_score, report.get('totalReports', 0), categories, country)
                        threats_detected += 1
                        
                        # Only count as NEW threat if it wasn't a threat before
                        if not was_threat:
                            new_threats_detected += 1
                            log_message(f"🚨 NEW THREAT DETECTED: {ip} (Score: {abuse_score}%, Level: {get_threat_level_text(threat_level)})")
                        else:
                            log_message(f"Updated existing threat: {ip} (Score: {abuse_score}%, Level: {get_threat_level_text(threat_level)})")

                        # Initialize ntfy client if enabled
                        ntfy_client = None
                        if config.get('ntfy_enabled', False):
                            try:
                                ntfy_client = NtfyClient(config)
                                log_message(f"ntfy client initialized successfully - will notify on malicious: {config.get('ntfy_notify_malicious', True)}, suspicious: {config.get('ntfy_notify_suspicious', False)}")
                            except Exception as e:
                                log_message(f"Failed to initialize ntfy client: {str(e)}")
                        else:
                            log_message("ntfy notifications disabled in configuration")

                        if ntfy_client and threat_level >= 1:
                            try:
                                log_message(f"Attempting to send ntfy notification for {ip} (threat_level: {threat_level}, score: {abuse_score}%)")
                                
                                # Send notification for detected threat
                                ntfy_result = ntfy_client.send_threat_notification(
                                    ip_address=ip,
                                    abuse_score=abuse_score,
                                    threat_level=threat_level,
                                    country=country,
                                    connection_details=connection_details,
                                    is_new_threat=not was_threat
                                )
                                
                                log_message(f"ntfy notification result for {ip}: {ntfy_result['status']} - {ntfy_result.get('message', 'no message')}")
                                
                                if ntfy_result['status'] == 'success':
                                    log_message(f"✓ ntfy notification sent successfully for {ip}")
                                elif ntfy_result['status'] == 'skipped':
                                    log_message(f"ntfy notification skipped for {ip}: {ntfy_result.get('reason', 'unknown reason')}")
                                else:
                                    log_message(f"✗ ntfy notification failed for {ip}: {ntfy_result['message']}")
                                    
                            except Exception as e:
                                log_message(f"Exception sending ntfy notification for {ip}: {str(e)}")
                                import traceback
                                log_message(f"Full traceback: {traceback.format_exc()}")
                        else:
                            if threat_level >= 1:
                                log_message(f"No ntfy notification sent for {ip} - ntfy_client: {ntfy_client is not None}, threat_level: {threat_level}")
                    else:
                        # Remove from threats if now safe
                        if was_threat:
                            log_message(f"IP now safe (removed from threats): {ip}")
                        self.db_manager.remove_threat(ip)
                    
                    ips_checked += 1
                    time.sleep(0.3)  # Rate limiting
                    


            except Exception as e:
                log_message(f"Error checking IP {ip}: {str(e)}")
                continue
        
        return {
            'status': 'ok',
            'ips_checked': ips_checked,
            'threats_detected': threats_detected,
            'new_threats_detected': new_threats_detected,
            'message': f'Enhanced batch processed: {ips_checked} checked, {threats_detected} threats ({new_threats_detected} new)'
        }
   
    def _extract_categories(self, report):
        """Extract categories from API report"""
        categories = ''
        if 'reports' in report and report['reports'] and len(report['reports']) > 0:
            if 'categories' in report['reports'][0]:
                categories = ','.join(str(cat) for cat in report['reports'][0]['categories'])
        return categories
    
    def _update_batch_stats(self, result):
        """Update database statistics after batch processing"""
        if result['status'] == 'ok':
            current_daily = int(self.db_manager.get_stat('daily_checks', '0'))
            self.db_manager.update_stat('daily_checks', current_daily + result['ips_checked'])
            
            total_checks = int(self.db_manager.get_stat('total_checks', '0'))
            self.db_manager.update_stat('total_checks', total_checks + result['ips_checked'])
            
            from .core_utils import get_db_timestamp
            self.db_manager.update_stat('last_check', get_db_timestamp())

    def _auto_update_alias(self, config, new_threats_count):
        """Automatically update alias when NEW threats detected"""
        try:
            if not config['alias_enabled']:
                return
            
            if not config.get('opnsense_api_key') or not config.get('opnsense_api_secret'):
                log_message("New threats detected but API credentials missing for alias updates")
                return
            
            log_message(f"Auto-updating alias: {new_threats_count} NEW threats detected")
            
            # Call the alias update script
            result = subprocess.run([
                '/usr/local/bin/python3',
                '/usr/local/opnsense/scripts/AbuseIPDBChecker/manage_alias.py',
                'update'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                try:
                    alias_result = json.loads(result.stdout)
                    if alias_result.get('status') == 'ok':
                        log_message(f"✓ Alias auto-updated: {alias_result.get('ip_count', 0)} IPs")
                    else:
                        log_message(f"Alias update warning: {alias_result.get('message', 'Unknown issue')}")
                except json.JSONDecodeError:
                    log_message(f"Alias update completed: {result.stdout.strip()}")
            else:
                log_message(f"Alias update failed: {result.stderr.strip()}")
                
        except Exception as e:
            log_message(f"Error in auto-alias update: {str(e)}")

    def _log_batch_result(self, result):
        """Log enhanced batch processing results"""
        if result['status'] == 'ok':
            log_message(f"Enhanced batch completed: {result['ips_checked']} checked, {result['threats_detected']} threats, {result.get('skipped', 0)} skipped")
            if result['threats_detected'] > 0:
                log_message(f"⚠️  THREATS DETECTED: {result['threats_detected']} malicious IPs found with port information!")
        else:
            log_message(f"Enhanced batch failed: {result['message']}")
    
    def get_daemon_status(self):
        """Get current daemon status and recent activity"""
        try:
            # Check if daemon is running
            result = subprocess.run(['pgrep', '-f', 'checker.py daemon'], 
                                  capture_output=True, text=True)
            daemon_running = bool(result.stdout.strip())
            
            # Get recent batch activity from logs
            recent_batches = self._get_recent_batch_activity()
            
            # Get configuration
            config = self.config_manager.get_config() if self.config_manager else {}
            
            # Get current stats
            stats = self.db_manager.get_statistics_summary(config) if self.db_manager else {}
            
            return {
                'status': 'ok',
                'daemon_running': daemon_running,
                'daemon_pid': result.stdout.strip() if daemon_running else None,
                'batch_interval': f'{self.batch_interval} seconds',
                'poll_interval': f'{self.poll_interval} seconds',
                'recent_batches': recent_batches,
                'daily_checks_used': stats.get('daily_checks', '0'),
                'daily_limit': config.get('daily_check_limit', 100),
                'api_configured': bool(config.get('api_key') and config.get('api_key') != 'YOUR_API_KEY'),
                'alias_configured': bool(config.get('opnsense_api_key') and config.get('opnsense_api_secret')),
                'enhanced_features': 'Port tracking enabled'
            }
            
        except Exception as e:
            return {'status': 'error', 'message': f'Error getting daemon status: {str(e)}'}
    
    def _get_recent_batch_activity(self):
        """Get recent batch activity from logs"""
        from .core_utils import LOG_FILE
        recent_batches = []
        
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()[-100:]  # Last 100 lines
                    
                for line in reversed(lines):
                    if ('BATCH PROCESSING:' in line or 'batch completed:' in line or 
                        'Enhanced batch' in line or 'NEW THREAT DETECTED:' in line):
                        recent_batches.append(line.strip())
                        if len(recent_batches) >= 10:  # Last 10 batch operations
                            break
            except Exception:
                pass
        
        return recent_batches

# Utility functions for backward compatibility
def run_daemon():
    """Entry point for daemon mode - creates dependencies locally"""
    from .config_manager import ConfigManager
    from .database import DatabaseManager
    
    config_manager = ConfigManager()
    db_manager = DatabaseManager()
    manager = DaemonManager(config_manager, db_manager)
    manager.start_daemon()

def get_batch_status():
    """Get batch processing status - creates dependencies locally"""
    from .config_manager import ConfigManager
    from .database import DatabaseManager
    
    config_manager = ConfigManager()
    db_manager = DatabaseManager()
    manager = DaemonManager(config_manager, db_manager)
    return manager.get_daemon_status()