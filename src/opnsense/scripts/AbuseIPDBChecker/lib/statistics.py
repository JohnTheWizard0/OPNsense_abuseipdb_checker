#!/usr/local/bin/python3

"""
Enhanced Statistics Manager Module
Handles all statistics collection, reporting, and data export operations with new features
"""

import os
import json
from .core_utils import log_message, get_threat_level_text
from .database import DatabaseManager

class StatisticsManager:
    """Enhanced statistics management and reporting with new features"""
    
    def __init__(self, db_manager=None):
        self.db = db_manager or DatabaseManager()
    
    def get_comprehensive_stats(self, config=None):
        """Get comprehensive statistics with enhanced threat breakdown and marked safe counts"""
        try:
            stats = self.db.get_statistics_summary(config)
            
            # Enhanced breakdown info for transparency
            breakdown_info = f"Malicious: {stats['malicious_count']}"
            if config and config.get('alias_include_suspicious', False):
                breakdown_info += f", Suspicious: {stats['suspicious_count']}"
            else:
                breakdown_info += f" (excluding {stats['suspicious_count']} suspicious)"
            
            # Add marked safe information
            if stats.get('marked_safe_count', 0) > 0:
                breakdown_info += f", Marked Safe: {stats['marked_safe_count']}"
            
            # Add configuration context
            daily_limit = config['daily_check_limit'] if config else 100
            
            return {
                'status': 'ok',
                'total_ips': stats['total_ips'],
                'total_threats': stats['total_threats'],
                'malicious_count': stats['malicious_count'],
                'suspicious_count': stats['suspicious_count'],
                'marked_safe_count': stats.get('marked_safe_count', 0),
                'threat_breakdown': breakdown_info,
                'alias_includes_suspicious': config.get('alias_include_suspicious', False) if config else False,
                'last_check': stats['last_check'],
                'daily_checks': stats['daily_checks'],
                'daily_limit': daily_limit,
                'total_checks': stats['total_checks'],
                'features': 'Enhanced with port tracking and IP management'
            }
            
        except Exception as e:
            log_message(f"Error retrieving comprehensive statistics: {str(e)}")
            return {'status': 'error', 'message': f'Error retrieving statistics: {str(e)}'}

    def get_recent_threats(self, limit=20, offset=0, search_ip='', include_marked_safe=True):
        """Get recent threats - FIXED for sqlite3.Row objects"""
        try:
            result = self.db.get_recent_threats(limit, offset, search_ip, include_marked_safe)
            
            threats = []
            for row in result['threats']:
                # Convert sqlite3.Row to dict for safe access
                row_dict = dict(row) if hasattr(row, 'keys') else row
                
                threat_data = {
                    'ip': row_dict.get('ip') or 'Unknown',
                    'score': row_dict.get('abuse_score') or 0,
                    'reports': row_dict.get('reports') or 0,
                    'last_seen': row_dict.get('last_seen') or 'Never',
                    'country': row_dict.get('country') or 'Unknown',
                    'categories': row_dict.get('categories') or '',
                    'connection_details': row_dict.get('connection_details') or '',
                    'marked_safe': bool(row_dict.get('marked_safe')) if row_dict.get('marked_safe') is not None else False,
                    'marked_safe_date': row_dict.get('marked_safe_date') or '',
                    'marked_safe_by': row_dict.get('marked_safe_by') or ''
                }
                threats.append(threat_data)
            
            return {
                'status': 'ok',
                'threats': threats,
                'total_count': result.get('total_count', 0),
                'limit': limit,
                'offset': offset,
                'search_query': search_ip,
                'include_marked_safe': include_marked_safe
            }
            
        except Exception as e:
            log_message(f"Error retrieving recent threats: {str(e)}")
            return {
                'status': 'error', 
                'message': f'Error retrieving threats: {str(e)}',
                'threats': [],
                'total_count': 0,
                'limit': limit,
                'offset': offset
            }

    def get_all_checked_ips(self, limit=20, offset=0, search_ip=''):
        """Get all checked IPs - FIXED for sqlite3.Row objects"""
        try:
            result = self.db.get_all_checked_ips(limit, offset, search_ip)
            
            ips = []
            for row in result['ips']:
                # Convert sqlite3.Row to dict for safe access
                row_dict = dict(row) if hasattr(row, 'keys') else row
                
                threat_level = row_dict.get('threat_level') or 0
                ip_data = {
                    'ip': row_dict.get('ip') or 'Unknown',
                    'last_checked': row_dict.get('last_checked') or 'Never',
                    'threat_level': threat_level,
                    'threat_text': get_threat_level_text(threat_level),
                    'check_count': row_dict.get('check_count') or 0,
                    'abuse_score': row_dict.get('abuse_score') or 0,
                    'reports': row_dict.get('reports') or 0,
                    'country': row_dict.get('country') or 'Unknown',
                    'categories': row_dict.get('categories') or '',
                    'connection_details': row_dict.get('connection_details') or '',
                    'marked_safe': bool(row_dict.get('marked_safe')) if row_dict.get('marked_safe') is not None else False,
                    'marked_safe_date': row_dict.get('marked_safe_date') or '',
                    'marked_safe_by': row_dict.get('marked_safe_by') or ''
                }
                ips.append(ip_data)
            
            return {
                'status': 'ok',
                'ips': ips,
                'total_count': result.get('total_count', 0),
                'limit': limit,
                'offset': offset,
                'search_query': search_ip
            }
            
        except Exception as e:
            log_message(f"Error retrieving all checked IPs: {str(e)}")
            return {
                'status': 'error', 
                'message': f'Error retrieving checked IPs: {str(e)}',
                'ips': [],
                'total_count': 0,
                'limit': limit,
                'offset': offset
            }

    def export_threats_data(self, format='json', include_suspicious=False, include_marked_safe=False):
        """Export threats data in various formats with enhanced filtering"""
        try:
            min_threat_level = 1 if include_suspicious else 2
            threats_data = self.db.get_threat_ips_for_alias(min_threat_level, max_hosts=10000)
            
            # Filter out marked safe if requested
            if not include_marked_safe:
                # Get all marked safe IPs
                marked_safe_ips = set()
                try:
                    marked_safe_result = self.db.execute_query(
                        'SELECT ip FROM threats WHERE marked_safe = 1',
                        fetch_all=True
                    )
                    marked_safe_ips = {row['ip'] for row in marked_safe_result}
                except Exception:
                    pass
                
                # Filter out marked safe IPs
                threats_data = [row for row in threats_data if row['ip'] not in marked_safe_ips]
            
            if format.lower() == 'json':
                return self._export_json_enhanced(threats_data)
            elif format.lower() == 'csv':
                return self._export_csv_enhanced(threats_data)
            elif format.lower() == 'txt':
                return self._export_txt_enhanced(threats_data)
            else:
                return {'status': 'error', 'message': f'Unsupported format: {format}'}
                
        except Exception as e:
            log_message(f"Error exporting threats data: {str(e)}")
            return {'status': 'error', 'message': f'Error exporting data: {str(e)}'}
    
    def _export_json_enhanced(self, threats_data):
        """Export threats as enhanced JSON with metadata"""
        threats_list = []
        for row in threats_data:
            threats_list.append({
                'ip': row['ip'],
                'abuse_score': row['abuse_score'],
                'threat_level': 'malicious' if row['abuse_score'] >= 70 else 'suspicious'
            })
        
        export_data = {
            'export_timestamp': get_threat_level_text(0),  # Using format_timestamp function
            'total_threats': len(threats_list),
            'threats': threats_list,
            'format': 'enhanced_json'
        }
        
        return {
            'status': 'ok',
            'format': 'json',
            'data': json.dumps(export_data, indent=2),
            'count': len(threats_list)
        }
    
    def _export_csv_enhanced(self, threats_data):
        """Export threats as enhanced CSV with headers"""
        csv_lines = ['ip,abuse_score,threat_level']
        for row in threats_data:
            threat_level = 'malicious' if row['abuse_score'] >= 70 else 'suspicious'
            csv_lines.append(f"{row['ip']},{row['abuse_score']},{threat_level}")
        
        return {
            'status': 'ok',
            'format': 'csv',
            'data': '\n'.join(csv_lines),
            'count': len(threats_data)
        }
    
    def _export_txt_enhanced(self, threats_data):
        """Export threats as enhanced plain text with comments"""
        lines = [
            f"# AbuseIPDB Threats Export",
            f"# Total threats: {len(threats_data)}",
            f"# Format: IP addresses (one per line)",
            ""
        ]
        
        ip_list = [row['ip'] for row in threats_data]
        lines.extend(ip_list)
        
        return {
            'status': 'ok',
            'format': 'txt',
            'data': '\n'.join(lines),
            'count': len(ip_list)
        }
    
    def get_port_analysis(self, limit=50):
        """Get analysis of most commonly accessed ports by threats"""
        try:
            # Get all threats with port information
            query = '''
                SELECT ci.destination_port, COUNT(*) as threat_count, 
                       GROUP_CONCAT(DISTINCT ci.ip) as threat_ips
                FROM checked_ips ci
                JOIN threats t ON ci.ip = t.ip
                WHERE ci.destination_port != '' AND ci.destination_port IS NOT NULL
                  AND (t.marked_safe = 0 OR t.marked_safe IS NULL)
                GROUP BY ci.destination_port
                ORDER BY threat_count DESC
                LIMIT ?
            '''
            
            results = self.db.execute_query(query, (limit,), fetch_all=True)
            
            port_analysis = []
            for row in results:
                port_info = {
                    'ports': row['destination_port'],
                    'threat_count': row['threat_count'],
                    'sample_ips': row['threat_ips'].split(',')[:5] if row['threat_ips'] else []
                }
                port_analysis.append(port_info)
            
            return {
                'status': 'ok',
                'port_analysis': port_analysis,
                'total_analyzed': len(port_analysis)
            }
            
        except Exception as e:
            log_message(f"Error getting port analysis: {str(e)}")
            return {'status': 'error', 'message': f'Error analyzing ports: {str(e)}'}
    
    def get_country_analysis(self, limit=20):
        """Get analysis of threats by country"""
        try:
            query = '''
                SELECT ci.country, COUNT(*) as threat_count,
                       AVG(t.abuse_score) as avg_score,
                       MAX(t.abuse_score) as max_score
                FROM checked_ips ci
                JOIN threats t ON ci.ip = t.ip
                WHERE (t.marked_safe = 0 OR t.marked_safe IS NULL)
                GROUP BY ci.country
                ORDER BY threat_count DESC
                LIMIT ?
            '''
            
            results = self.db.execute_query(query, (limit,), fetch_all=True)
            
            country_analysis = []
            for row in results:
                country_info = {
                    'country': row['country'] or 'Unknown',
                    'threat_count': row['threat_count'],
                    'avg_abuse_score': round(row['avg_score'], 1) if row['avg_score'] else 0,
                    'max_abuse_score': row['max_score'] or 0
                }
                country_analysis.append(country_info)
            
            return {
                'status': 'ok',
                'country_analysis': country_analysis,
                'total_countries': len(country_analysis)
            }
            
        except Exception as e:
            log_message(f"Error getting country analysis: {str(e)}")
            return {'status': 'error', 'message': f'Error analyzing countries: {str(e)}'}
    
    def get_management_summary(self):
        """Get summary of IP management actions"""
        try:
            # Count marked safe IPs
            marked_safe_count = self.db.execute_query(
                'SELECT COUNT(*) as count FROM threats WHERE marked_safe = 1',
                fetch_one=True
            )['count']
            
            # Get recent management actions from logs
            recent_actions = []
            try:
                from .core_utils import LOG_FILE
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, 'r') as f:
                        lines = f.readlines()[-100:]
                        
                    for line in reversed(lines):
                        if any(keyword in line for keyword in ['Marked', 'Removed', 'Unmarked']):
                            recent_actions.append(line.strip())
                            if len(recent_actions) >= 10:
                                break
            except Exception:
                pass
            
            return {
                'status': 'ok',
                'marked_safe_count': marked_safe_count,
                'recent_actions': recent_actions,
                'management_features': ['Mark Safe', 'Remove IP', 'Unmark Safe', 'Port Tracking']
            }
            
        except Exception as e:
            log_message(f"Error getting management summary: {str(e)}")
            return {'status': 'error', 'message': f'Error getting management summary: {str(e)}'}