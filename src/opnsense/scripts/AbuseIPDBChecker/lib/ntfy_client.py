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
        
        # Handle priority safely
        priority_val = config.get('ntfy_priority', 3)
        try:
            if isinstance(priority_val, str):
                if priority_val == '' or priority_val == 'None':
                    self.priority = 3
                else:
                    self.priority = int(priority_val)
            else:
                self.priority = int(priority_val)
            # Clamp to valid range
            self.priority = max(1, min(5, self.priority))
        except (ValueError, TypeError):
            self.priority = 3
            
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
                f"Threat Level: {threat_text} ({abuse_score}%)"
            ]

            # Add country with flag
            country_flag = self._get_country_flag(country)
            country_display = f"{country} {country_flag}".strip() if country_flag else (country or "Unknown")
            message_parts.append(f"Country: {country_display}")

            # Determine action based on threat level and config
            if threat_level == 2:  # Malicious
                if self.config.get('alias_enabled', True):
                    action = "Added to MaliciousIPs alias"
                else:
                    action = "Detected (alias disabled)"
            elif threat_level == 1:  # Suspicious
                if self.config.get('alias_enabled', True) and self.config.get('alias_include_suspicious', False):
                    action = "Added to MaliciousIPs alias"
                else:
                    action = "Monitored (not blocked)"
            else:
                action = "Monitored"

            message_parts.append(f"Action: {action}")

            # Add connection details if enabled and available
            if self.include_connection_details and connection_details:
                conn_info = self._format_connection_details(connection_details)
                if conn_info['target_host'] and conn_info['ports_info']:
                    message_parts.append(f"Connection: to {conn_info['target_host']} ({conn_info['ports_info']})")
                elif conn_info['ports_info']:
                    message_parts.append(f"Connections: {conn_info['ports_info']}")
                elif conn_info['target_host']:
                    message_parts.append(f"Target: {conn_info['target_host']}")

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
        """Format connection details for notification - returns dict with target_host and ports_info"""
        if not connection_details:
            return {'target_host': '', 'ports_info': ''}
        
        try:
            ports = set()
            target_hosts = set()
            
            # Handle pipe-separated format (most common)
            if '|' in connection_details:
                connections = connection_details.split('|')
                for conn in connections:
                    if conn.strip() and (':' in conn):
                        # Extract destination IP and port from "sourceIP:port accessing destIP:port" format
                        if ' accessing ' in conn:
                            dest_part = conn.split(' accessing ')[-1].strip()
                            if ':' in dest_part:
                                dest_ip, port = dest_part.rsplit(':', 1)
                                if port.isdigit():
                                    ports.add(port)
                                    target_hosts.add(dest_ip)
                        elif ' accessed ' in conn:
                            dest_part = conn.split(' accessed ')[-1].strip()
                            if ':' in dest_part:
                                dest_ip, port = dest_part.rsplit(':', 1)
                                if port.isdigit():
                                    ports.add(port)
                                    target_hosts.add(dest_ip)
            
            # Handle single connection format
            elif ':' in connection_details:
                if ' accessing ' in connection_details:
                    dest_part = connection_details.split(' accessing ')[-1].strip()
                    if ':' in dest_part:
                        dest_ip, port = dest_part.rsplit(':', 1)
                        if port.isdigit():
                            ports.add(port)
                            target_hosts.add(dest_ip)
                elif ' accessed ' in connection_details:
                    dest_part = connection_details.split(' accessed ')[-1].strip()
                    if ':' in dest_part:
                        dest_ip, port = dest_part.rsplit(':', 1)
                        if port.isdigit():
                            ports.add(port)
                            target_hosts.add(dest_ip)
            
            # Format the outputs
            target_host = list(target_hosts)[0] if target_hosts else ""
            
            ports_info = ""
            if ports:
                # Sort ports numerically and limit to first 3
                sorted_ports = sorted(list(ports), key=lambda x: int(x))[:3]
                port_list = [f"Port {port}" for port in sorted_ports]
                ports_info = ', '.join(port_list)
                
                # Add indicator if there are more ports
                if len(ports) > 3:
                    ports_info += f" (+{len(ports)-3} more)"
            
            return {'target_host': target_host, 'ports_info': ports_info}
            
        except Exception as e:
            log_message(f"Error formatting connection details for ntfy: {str(e)}")
            return {'target_host': '', 'ports_info': 'Connection info'}

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
    
    def _get_country_flag(self, country_code):
        """Convert country code to flag emoji"""
        if not country_code or len(country_code) != 2:
            return ""
        
        # Most common country flags
        flag_map = {
            'AD': '🇦🇩', 'AE': '🇦🇪', 'AF': '🇦🇫', 'AG': '🇦🇬', 'AL': '🇦🇱', 'AM': '🇦🇲', 'AR': '🇦🇷',
            'AT': '🇦🇹', 'AU': '🇦🇺', 'AZ': '🇦🇿', 'BA': '🇧🇦', 'BB': '🇧🇧', 'BD': '🇧🇩', 'BE': '🇧🇪',
            'BG': '🇧🇬', 'BH': '🇧🇭', 'BO': '🇧🇴', 'BR': '🇧🇷', 'BS': '🇧🇸', 'BW': '🇧🇼', 'BY': '🇧🇾',
            'BZ': '🇧🇿', 'CA': '🇨🇦', 'CH': '🇨🇭', 'CL': '🇨🇱', 'CN': '🇨🇳', 'CO': '🇨🇴', 'CR': '🇨🇷',
            'CU': '🇨🇺', 'CY': '🇨🇾', 'CZ': '🇨🇿', 'DE': '🇩🇪', 'DK': '🇩🇰', 'DO': '🇩🇴', 'DZ': '🇩🇿',
            'EC': '🇪🇨', 'EE': '🇪🇪', 'EG': '🇪🇬', 'ES': '🇪🇸', 'ET': '🇪🇹', 'FI': '🇫🇮', 'FJ': '🇫🇯',
            'FR': '🇫🇷', 'GB': '🇬🇧', 'GE': '🇬🇪', 'GH': '🇬🇭', 'GR': '🇬🇷', 'GT': '🇬🇹', 'HK': '🇭🇰',
            'HN': '🇭🇳', 'HR': '🇭🇷', 'HT': '🇭🇹', 'HU': '🇭🇺', 'ID': '🇮🇩', 'IE': '🇮🇪', 'IL': '🇮🇱',
            'IN': '🇮🇳', 'IQ': '🇮🇶', 'IR': '🇮🇷', 'IS': '🇮🇸', 'IT': '🇮🇹', 'JM': '🇯🇲', 'JO': '🇯🇴',
            'JP': '🇯🇵', 'KE': '🇰🇪', 'KG': '🇰🇬', 'KH': '🇰🇭', 'KP': '🇰🇵', 'KR': '🇰🇷', 'KW': '🇰🇼',
            'KZ': '🇰🇿', 'LA': '🇱🇦', 'LB': '🇱🇧', 'LI': '🇱🇮', 'LK': '🇱🇰', 'LT': '🇱🇹', 'LU': '🇱🇺',
            'LV': '🇱🇻', 'LY': '🇱🇾', 'MA': '🇲🇦', 'MD': '🇲🇩', 'ME': '🇲🇪', 'MK': '🇲🇰', 'MM': '🇲🇲',
            'MN': '🇲🇳', 'MO': '🇲🇴', 'MX': '🇲🇽', 'MY': '🇲🇾', 'MZ': '🇲🇿', 'NA': '🇳🇦', 'NG': '🇳🇬',
            'NI': '🇳🇮', 'NL': '🇳🇱', 'NO': '🇳🇴', 'NP': '🇳🇵', 'NZ': '🇳🇿', 'OM': '🇴🇲', 'PA': '🇵🇦',
            'PE': '🇵🇪', 'PH': '🇵🇭', 'PK': '🇵🇰', 'PL': '🇵🇱', 'PT': '🇵🇹', 'PY': '🇵🇾', 'QA': '🇶🇦',
            'RO': '🇷🇴', 'RS': '🇷🇸', 'RU': '🇷🇺', 'RW': '🇷🇼', 'SA': '🇸🇦', 'SD': '🇸🇩', 'SE': '🇸🇪',
            'SG': '🇸🇬', 'SI': '🇸🇮', 'SK': '🇸🇰', 'SO': '🇸🇴', 'SY': '🇸🇾', 'TH': '🇹🇭', 'TJ': '🇹🇯',
            'TN': '🇹🇳', 'TR': '🇹🇷', 'TW': '🇹🇼', 'TZ': '🇹🇿', 'UA': '🇺🇦', 'UG': '🇺🇬', 'US': '🇺🇸',
            'UY': '🇺🇾', 'UZ': '🇺🇿', 'VE': '🇻🇪', 'VN': '🇻🇳', 'YE': '🇾🇪', 'ZA': '🇿🇦', 'ZM': '🇿🇲',
            'ZW': '🇿🇼'
        }
        
        return flag_map.get(country_code.upper(), "")