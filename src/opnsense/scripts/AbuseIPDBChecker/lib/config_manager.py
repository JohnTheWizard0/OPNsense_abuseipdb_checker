#!/usr/local/bin/python3

"""
Configuration Manager Module
Handles all configuration reading and validation
"""

import os
from configparser import ConfigParser
from .core_utils import log_message, CONFIG_DIR

CONFIG_FILE = os.path.join(CONFIG_DIR, 'abuseipdbchecker.conf')

class ConfigManager:
    """Centralized configuration management"""
    
    def __init__(self):
        self._config = None
        self._load_config()
    
    def _get_default_config(self):
        """Return default configuration values"""
        return {
            'log_file': '/var/log/filter/latest.log',
            'check_frequency': 7,
            'suspicious_threshold': 40,
            'malicious_threshold': 70,
            'ignore_blocked_connections': True,
            'lan_subnets': ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
            'ignore_protocols': ['icmp', 'igmp'],
            'api_key': '',
            'api_endpoint': 'https://api.abuseipdb.com/api/v2/check',
            'max_age': 90,
            'daily_check_limit': 100,
            'alias_enabled': True,
            'alias_include_suspicious': False,
            'alias_max_recent_hosts': 500,
            'opnsense_api_key': '',
            'opnsense_api_secret': '',
            'ntfy_enabled': False,
            'ntfy_server': 'https://ntfy.sh',
            'ntfy_topic': 'abuseipdb-alerts',
            'ntfy_token': '',
            'ntfy_notify_malicious': True,
            'ntfy_notify_suspicious': False,
            'ntfy_priority': 3,
            'ntfy_include_connection_details': True,
        }
    
    def _load_config(self):
        """Load configuration from OPNsense config file"""
        self._config = self._get_default_config()
        
        if not os.path.exists(CONFIG_FILE):
            log_message(f"Config file not found: {CONFIG_FILE}, using defaults")
            return
        
        try:
            cp = ConfigParser()
            cp.read(CONFIG_FILE)
            
            # General section - Remove Enabled loading
            if cp.has_section('general'):
                self._load_general_section(cp)
            
            # Network section
            if cp.has_section('network'):
                self._load_network_section(cp)
            
            # API section
            if cp.has_section('api'):
                self._load_api_section(cp)
            
            # Alias section
            if cp.has_section('alias'):
                self._load_alias_section(cp)

            # ntfy section
            if cp.has_section('ntfy'):
                self._load_ntfy_section(cp)
                
        except Exception as e:
            log_message(f"Error reading config: {str(e)}")
    
    def _load_general_section(self, cp):
        """Load general configuration section"""
        section = 'general'
        
        # Remove Enabled loading completely
        if cp.has_option(section, 'LogFile'):
            self._config['log_file'] = cp.get(section, 'LogFile')
        if cp.has_option(section, 'CheckFrequency'):
            self._config['check_frequency'] = int(cp.get(section, 'CheckFrequency'))
        if cp.has_option(section, 'SuspiciousThreshold'):
            self._config['suspicious_threshold'] = int(cp.get(section, 'SuspiciousThreshold'))
        if cp.has_option(section, 'MaliciousThreshold'):
            self._config['malicious_threshold'] = int(cp.get(section, 'MaliciousThreshold'))
        if cp.has_option(section, 'IgnoreBlockedConnections'):
            self._config['ignore_blocked_connections'] = cp.get(section, 'IgnoreBlockedConnections') == '1'
        if cp.has_option(section, 'ApiKey'):
            self._config['opnsense_api_key'] = cp.get(section, 'ApiKey')
        if cp.has_option(section, 'ApiSecret'):
            self._config['opnsense_api_secret'] = cp.get(section, 'ApiSecret')
    
    def _load_network_section(self, cp):
        """Load network configuration section"""
        section = 'network'
        
        if cp.has_option(section, 'LanSubnets'):
            subnets = cp.get(section, 'LanSubnets')
            self._config['lan_subnets'] = [subnet.strip() for subnet in subnets.split(',')]
        if cp.has_option(section, 'IgnoreProtocols'):
            protocols = cp.get(section, 'IgnoreProtocols')
            self._config['ignore_protocols'] = [proto.strip() for proto in protocols.split(',')]
    
    def _load_api_section(self, cp):
        """Load API configuration section"""
        section = 'api'
        
        if cp.has_option(section, 'Key'):
            self._config['api_key'] = cp.get(section, 'Key')
        if cp.has_option(section, 'Endpoint'):
            self._config['api_endpoint'] = cp.get(section, 'Endpoint')
        if cp.has_option(section, 'MaxAge'):
            self._config['max_age'] = int(cp.get(section, 'MaxAge'))
        if cp.has_option(section, 'DailyCheckLimit'):
            self._config['daily_check_limit'] = int(cp.get(section, 'DailyCheckLimit'))
    
    def _load_alias_section(self, cp):
        """Load alias configuration section"""
        section = 'alias'
        
        if cp.has_option(section, 'Enabled'):
            self._config['alias_enabled'] = cp.get(section, 'Enabled') == '1'
        if cp.has_option(section, 'IncludeSuspicious'):
            self._config['alias_include_suspicious'] = cp.get(section, 'IncludeSuspicious') == '1'
        if cp.has_option(section, 'MaxRecentHosts'):
            self._config['alias_max_recent_hosts'] = int(cp.get(section, 'MaxRecentHosts'))

    def _load_ntfy_section(self, cp):
        """Load ntfy configuration section"""
        section = 'ntfy'
        
        if cp.has_option(section, 'Enabled'):
            self._config['ntfy_enabled'] = cp.get(section, 'Enabled') == '1'
        if cp.has_option(section, 'Server'):
            self._config['ntfy_server'] = cp.get(section, 'Server')
        if cp.has_option(section, 'Topic'):
            self._config['ntfy_topic'] = cp.get(section, 'Topic')
        if cp.has_option(section, 'Token'):
            self._config['ntfy_token'] = cp.get(section, 'Token')
        if cp.has_option(section, 'NotifyMalicious'):
            self._config['ntfy_notify_malicious'] = cp.get(section, 'NotifyMalicious') == '1'
        if cp.has_option(section, 'NotifySuspicious'):
            self._config['ntfy_notify_suspicious'] = cp.get(section, 'NotifySuspicious') == '1'
        if cp.has_option(section, 'Priority'):
            self._config['ntfy_priority'] = int(cp.get(section, 'Priority'))
        if cp.has_option(section, 'IncludeConnectionDetails'):
            self._config['ntfy_include_connection_details'] = cp.get(section, 'IncludeConnectionDetails') == '1'
    
    def get_config(self):
        """Get the complete configuration dictionary"""
        return self._config.copy()
    
    def get(self, key, default=None):
        """Get a specific configuration value"""
        return self._config.get(key, default)
    
    def is_enabled(self):
        """Service is always enabled when running - remove this check"""
        return True  # Always return True since service control handles enable/disable
    
    def validate_config(self):
        """Validate configuration and return validation errors"""
        errors = []
        warnings = []
        
        # Remove enabled check - validation always runs since service is running
        
        # Check API key
        if not self._config['api_key'] or self._config['api_key'] == 'YOUR_API_KEY':
            errors.append('AbuseIPDB API key is required')
        
        # Check daily limit
        if self._config['daily_check_limit'] < 1 or self._config['daily_check_limit'] > 1000:
            errors.append('Daily check limit must be between 1 and 1000')
        
        # Check thresholds
        if self._config['suspicious_threshold'] >= self._config['malicious_threshold']:
            errors.append('Suspicious threshold must be less than malicious threshold')
        
        # Check OPNsense API credentials for alias
        if self._config['alias_enabled']:
            if not self._config['opnsense_api_key'] or not self._config['opnsense_api_secret']:
                warnings.append('OPNsense API credentials missing - alias management will not work')
        
        # Check log file
        if not os.path.exists(self._config['log_file']):
            warnings.append(f"Log file not found: {self._config['log_file']}")
        
        return {'errors': errors, 'warnings': warnings}
    
    def reload(self):
        """Reload configuration from file"""
        self._load_config()
        log_message("Configuration reloaded")
    
    def __getitem__(self, key):
        """Allow dictionary-style access"""
        return self._config[key]
    
    def __contains__(self, key):
        """Allow 'in' operator"""
        return key in self._config

# Factory function for backward compatibility
def read_config():
    """Factory function that returns a configuration dictionary"""
    manager = ConfigManager()
    return manager.get_config()