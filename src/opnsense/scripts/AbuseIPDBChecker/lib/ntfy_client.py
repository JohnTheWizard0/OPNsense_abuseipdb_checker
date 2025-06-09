#!/usr/local/bin/python3

"""
ntfy Client Module
Handles sending notifications to ntfy servers for threat detections
"""

import requests
import json
import time
from .core_utils import log_message

class NtfyClient:
    """ntfy notification client for AbuseIPDB threat alerts"""
    
    def __init__(self, config):
        self.config = config
        self.enabled = config.get('ntfy_enabled', False)
        self.server = config.get('ntfy_server', 'https://ntfy.sh')
        self.topic = config.get('ntfy_topic', 'abuseipdb-alerts')
        self.token = config.get('ntfy_token', '')
        self.notify_malicious = config.get('ntfy_notify_malicious', True)
        self.notify_suspicious = config.get('ntfy_notify_suspicious', False)
        self.priority = config.get('ntfy_priority', 3)
        self.include_connection_details = config.get('ntfy_include_connection_details', True)
        
        # Ensure server URL ends with topic
        if not self.server.endswith('/'):
            self.server += '/'
        self.url = f"{self.server}{self.topic}"
    
    def should_notify(self, threat_level, abuse_score):
        """Determine if notification should be sent based on threat level and config"""
        if not self.enabled:
            return False
        
        if threat_level == 2 and self.notify_malicious:  # Malicious
            return True
        elif threat_level == 1 and self.notify_suspicious:  # Suspicious
            return True
        
        return False
    def send_threat_notification(self, ip_address, abuse_score, threat_level, country='Unknown', 
                            connection_details='', is_new_threat=False):
        """Send ntfy notification for detected threat"""
        
        if not self.should_notify(threat_level, abuse_score):
            return {'status': 'skipped', 'reason': 'notification disabled for this threat level'}
        
        try:
            # Determine threat text and action (no emojis)
            if threat_level == 2:
                threat_text = "MALICIOUS"
                action = "Added to MaliciousIPs alias"
            elif threat_level == 1:
                threat_text = "SUSPICIOUS" 
                action = "Monitored (not blocked)"
            else:
                return {'status': 'skipped', 'reason': 'threat level too low'}
            
            # Build notification title (no emojis)
            status_text = "NEW" if is_new_threat else "UPDATED"
            title = f"{status_text} {threat_text} IP Detected"
            
            # Build message content
            message_parts = [
                f"Host: {ip_address}",
                f"Threat Level: {threat_text} ({abuse_score}%)",
                f"Country: {country}",
                f"Action: {action}"
            ]
            
            # Add connection details if enabled and available
            if self.include_connection_details and connection_details:
                connection_info = self._format_connection_details(connection_details)
                if connection_info:
                    message_parts.append(f"Connections: {connection_info}")
            
            message = "\n".join(message_parts)
            
            # Prepare headers with explicit UTF-8
            headers = {
                'Content-Type': 'text/plain; charset=utf-8',
                'User-Agent': 'OPNsense-AbuseIPDB-Checker/1.0',
                'Title': title,
                'Priority': str(self.priority),
                'Tags': 'warning,security,firewall'
            }
            
            # Add authentication if token provided
            if self.token:
                headers['Authorization'] = f'Bearer {self.token}'
            
            # Add click action to view IP details
            headers['Click'] = f'https://www.abuseipdb.com/check/{ip_address}'
            
            # Send notification with explicit UTF-8 encoding
            response = requests.post(
                self.url,
                data=message.encode('utf-8'),  # Explicit UTF-8 encoding
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                log_message(f"ntfy notification sent successfully for {ip_address} ({threat_text})")
                return {
                    'status': 'success',
                    'message': f'Notification sent for {ip_address}',
                    'threat_level': threat_text,
                    'abuse_score': abuse_score
                }
            else:
                error_msg = f"ntfy notification failed: HTTP {response.status_code} - {response.text}"
                log_message(error_msg)
                return {
                    'status': 'error',
                    'message': error_msg,
                    'http_code': response.status_code
                }
                
        except requests.exceptions.RequestException as e:
            error_msg = f"ntfy notification request failed: {str(e)}"
            log_message(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'exception': str(e)
            }
        except Exception as e:
            error_msg = f"ntfy notification error: {str(e)}"
            log_message(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'exception': str(e)
            }
    
    def _format_connection_details(self, connection_details):
        """Format connection details for notification"""
        if not connection_details:
            return ""
        
        try:
            # Handle pipe-separated format
            if '|' in connection_details:
                connections = connection_details.split('|')
                # Take first 2 connections to keep notification concise
                formatted_connections = []
                for conn in connections[:2]:
                    if 'accessing' in conn:
                        # Extract port information
                        parts = conn.split(' accessing ')
                        if len(parts) == 2:
                            source_part = parts[0]
                            dest_part = parts[1]
                            
                            # Extract source port
                            if ':' in source_part:
                                source_port = source_part.split(':')[-1]
                            else:
                                source_port = 'unknown'
                            
                            # Extract destination port
                            if ':' in dest_part:
                                dest_port = dest_part.split(':')[-1]
                            else:
                                dest_port = 'unknown'
                            
                            formatted_connections.append(f"Port {dest_port}")
                
                if formatted_connections:
                    result = ', '.join(formatted_connections)
                    if len(connections) > 2:
                        result += f" (+{len(connections)-2} more)"
                    return result
            
            # Fallback: just return first part of connection details
            return connection_details.split('|')[0][:50] + "..." if len(connection_details) > 50 else connection_details
            
        except Exception as e:
            log_message(f"Error formatting connection details for ntfy: {str(e)}")
            return "Multiple connections"
   
    def test_notification(self):
        """Send test notification to verify configuration"""
        if not self.enabled:
            return {'status': 'error', 'message': 'ntfy notifications are disabled'}
        
        try:
            headers = {
                'Content-Type': 'text/plain; charset=utf-8',
                'User-Agent': 'OPNsense-AbuseIPDB-Checker/1.0',
                'Title': 'AbuseIPDB Test Notification',  # Remove emoji
                'Priority': str(self.priority),
                'Tags': 'test,security'
            }
            
            if self.token:
                headers['Authorization'] = f'Bearer {self.token}'
            
            test_message = (
                "This is a test notification from AbuseIPDB Checker\n"
                f"Server: {self.server}\n"
                f"Topic: {self.topic}\n"
                f"Priority: {self.priority}\n"
                "Configuration is working correctly!"
            )
            
            response = requests.post(
                self.url,
                data=test_message.encode('utf-8'),  # Explicit UTF-8 encoding
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                log_message("ntfy test notification sent successfully")
                return {
                    'status': 'success',
                    'message': 'Test notification sent successfully',
                    'server': self.server,
                    'topic': self.topic
                }
            else:
                error_msg = f"Test notification failed: HTTP {response.status_code} - {response.text}"
                log_message(error_msg)
                return {
                    'status': 'error',
                    'message': error_msg,
                    'http_code': response.status_code
                }
                
        except Exception as e:
            error_msg = f"Test notification error: {str(e)}"
            log_message(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'exception': str(e)
            }

    def get_status(self):
        """Get current ntfy client status"""
        return {
            'enabled': self.enabled,
            'server': self.server,
            'topic': self.topic,
            'has_token': bool(self.token),
            'notify_malicious': self.notify_malicious,
            'notify_suspicious': self.notify_suspicious,
            'priority': self.priority,
            'include_connection_details': self.include_connection_details,
            'url': self.url
        }