#!/usr/local/bin/python3

"""
AbuseIPDB Checker Library Package
Compartmentalized modules for better debugging and maintenance
"""

__version__ = "1.0.0"

# Import in dependency order to avoid circular imports
try:
    from .core_utils import (
        log_message, 
        get_local_time, 
        format_timestamp,
        get_db_timestamp,
        ensure_directories,
        classify_threat_level,
        get_threat_level_text,
        system_log,
        log_timezone_info
    )
    
    from .config_manager import ConfigManager
    from .database import DatabaseManager
    from .api_client import AbuseIPDBClient
    from .log_parser import FirewallLogParser
    from .statistics import StatisticsManager
    from .daemon import DaemonManager
    
except ImportError as e:
    import sys
    print(f"Error in lib module imports: {str(e)}", file=sys.stderr)
    raise

__all__ = [
    'log_message',
    'get_local_time', 
    'format_timestamp',
    'get_db_timestamp',
    'ensure_directories',
    'classify_threat_level',
    'get_threat_level_text',
    'system_log',
    'log_timezone_info',
    'ConfigManager',
    'DatabaseManager', 
    'AbuseIPDBClient',
    'FirewallLogParser',
    'StatisticsManager',
    'DaemonManager'
]