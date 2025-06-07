#!/usr/local/bin/python3

"""
Statistics Manager Module
Handles all statistics collection, reporting, and data export operations
"""

import os
import json
from .core_utils import log_message, get_threat_level_text
from .database import DatabaseManager

class StatisticsManager:
    """Centralized statistics management and reporting"""
    
    def __init__(self, db_manager=None):
        self.db = db_manager or DatabaseManager()
    
    def get_comprehensive_stats(self, config=None):
        """Get comprehensive statistics with threat breakdown"""
        try:
            stats = self.db.get_statistics_summary(config)
            
            # Add breakdown info for transparency
            breakdown_info = f"Malicious: {stats['malicious_count']}"
            if config and config.get('alias_include_suspicious', False):
                breakdown_info += f", Suspicious: {stats['suspicious_count']}"
            else:
                breakdown_info += f" (excluding {stats['suspicious_count']} suspicious)"
            
            # Add configuration context
            daily_limit = config['daily_check_limit'] if config else 100
            
            return {
                'status': 'ok',
                'total_ips': stats['total_ips'],
                'total_threats': stats['total_threats'],
                'malicious_count': stats['malicious_count'],
                'suspicious_count': stats['suspicious_count'],
                'threat_breakdown': breakdown_info,
                'alias_includes_suspicious': config.get('alias_include_suspicious', False) if config else False,
                'last_check': stats['last_check'],
                'daily_checks': stats['daily_checks'],
                'daily_limit': daily_limit,
                'total_checks': stats['total_checks']
            }
            
        except Exception as e:
            log_message(f"Error retrieving comprehensive statistics: {str(e)}")
            return {'status': 'error', 'message': f'Error retrieving statistics: {str(e)}'}
    
    def get_recent_threats(self, limit=20):
        """Get recent threats with formatted data"""
        try:
            threats_data = self.db.get_recent_threats(limit)
            
            threats = []
            for row in threats_data:
                threats.append({
                    'ip': row['ip'],
                    'score': row['abuse_score'],
                    'reports': row['reports'],
                    'last_seen': row['last_seen'],
                    'country': row['country'],
                    'categories': row['categories']
                })
            
            return {
                'status': 'ok',
                'threats': threats,
                'count': len(threats)
            }
            
        except Exception as e:
            log_message(f"Error retrieving recent threats: {str(e)}")
            return {'status': 'error', 'message': f'Error retrieving threats: {str(e)}'}
    
    def get_all_checked_ips(self, limit=100):
        """Get all checked IPs with classification and formatting"""
        try:
            ips_data = self.db.get_all_checked_ips(limit)
            
            ips = []
            for row in ips_data:
                threat_level = row['threat_level'] or 0
                ips.append({
                    'ip': row['ip'],
                    'last_checked': row['last_checked'],
                    'threat_level': threat_level,
                    'threat_text': get_threat_level_text(threat_level),
                    'check_count': row['check_count'],
                    'abuse_score': row['abuse_score'] or 0,
                    'reports': row['reports'] or 0,
                    'country': row['country'] or 'Unknown',
                    'categories': row['categories'] or ''
                })
            
            return {
                'status': 'ok',
                'ips': ips,
                'total_count': len(ips)
            }
            
        except Exception as e:
            log_message(f"Error retrieving all checked IPs: {str(e)}")
            return {'status': 'error', 'message': f'Error retrieving checked IPs: {str(e)}'}
    
    def export_threats_data(self, format='json', include_suspicious=False):
        """Export threats data in various formats"""
        try:
            min_threat_level = 1 if include_suspicious else 2
            threats_data = self.db.get_threat_ips_for_alias(min_threat_level, max_hosts=10000)
            
            if format.lower() == 'json':
                return self._export_json(threats_data)
            elif format.lower() == 'csv':
                return self._export_csv(threats_data)
            elif format.lower() == 'txt':
                return self._export_txt(threats_data)
            else:
                return {'status': 'error', 'message': f'Unsupported format: {format}'}
                
        except Exception as e:
            log_message(f"Error exporting threats data: {str(e)}")
            return {'status': 'error', 'message': f'Error exporting data: {str(e)}'}
    
    def _export_json(self, threats_data):
        """Export threats as JSON"""
        threats_list = []
        for row in threats_data:
            threats_list.append({
                'ip': row['ip'],
                'abuse_score': row['abuse_score']
            })
        
        return {
            'status': 'ok',
            'format': 'json',
            'data': json.dumps(threats_list, indent=2),
            'count': len(threats_list)
        }
    
    def _export_csv(self, threats_data):
        """Export threats as CSV"""
        csv_lines = ['ip,abuse_score']
        for row in threats_data:
            csv_lines.append(f"{row['ip']},{row['abuse_score']}")
        
        return {
            'status': 'ok',
            'format': 'csv',
            'data': '\n'.join(csv_lines),
            'count': len(threats_data)
        }
    
    def _export_txt(self, threats_data):
        """Export threats as plain text (IP list)"""
        ip_list = [row['ip'] for row in threats_data]
        
        return {
            'status': 'ok',
            'format': 'txt',
            'data': '\n'.join(ip_list),
            'count': len(ip_list)
        }