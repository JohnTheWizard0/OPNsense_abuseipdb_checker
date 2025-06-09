#!/usr/local/bin/python3

"""
Enhanced Firewall Log Parser Module
Handles parsing OPNsense firewall logs and extracting external IPs with port information
"""

import os
import ipaddress
from .core_utils import log_message

class FirewallLogParser:
    """Handles all firewall log parsing operations with port extraction"""
    
    def __init__(self, config):
        self.config = config
        self.lan_networks = self._parse_lan_networks()
    
    def _parse_lan_networks(self):
        """Convert LAN subnets to proper network objects"""
        networks = []
        for subnet in self.config['lan_subnets']:
            try:
                networks.append(ipaddress.ip_network(subnet.strip()))
            except ValueError:
                log_message(f"Invalid LAN subnet: {subnet}")
                continue
        return networks
    
    def parse_log_for_ips(self, recent_only=False):
        """Parse OPNsense firewall log for external IPs"""
        external_ips = set()
        
        if not os.path.exists(self.config['log_file']):
            log_message(f"Log file not found: {self.config['log_file']}")
            return external_ips
        
        try:
            with open(self.config['log_file'], 'r', encoding='utf-8', errors='ignore') as f:
                if recent_only:
                    # For daemon mode - only recent activity
                    lines = f.readlines()
                    lines = lines[-200:] if len(lines) > 200 else lines
                else:
                    # For full checking - process more lines
                    lines = f.readlines()
                    lines = lines[-1000:] if len(lines) > 1000 else lines
            
            for line in lines:
                if not line.strip() or 'filterlog' not in line:
                    continue
                
                ip = self._parse_log_line(line)
                if ip:
                    external_ips.add(ip)
                    
        except Exception as e:
            if not recent_only:
                log_message(f"Error reading log file: {str(e)}")
        
        return external_ips
    
    def parse_log_for_ips_with_connections(self, recent_only=False):
        """Parse OPNsense firewall log for external IPs with full connection details"""
        external_connections = {}  # ip -> set of connection strings
        
        if not os.path.exists(self.config['log_file']):
            log_message(f"Log file not found: {self.config['log_file']}")
            return external_connections
        
        try:
            with open(self.config['log_file'], 'r', encoding='utf-8', errors='ignore') as f:
                if recent_only:
                    lines = f.readlines()
                    lines = lines[-200:] if len(lines) > 200 else lines
                else:
                    lines = f.readlines()
                    lines = lines[-1000:] if len(lines) > 1000 else lines
            
            for line in lines:
                if not line.strip() or 'filterlog' not in line:
                    continue
                
                connection_info = self._parse_log_line_with_connection(line)
                if connection_info:
                    external_ip = connection_info['external_ip']
                    connection_string = connection_info['connection_string']
                    
                    if external_ip not in external_connections:
                        external_connections[external_ip] = set()
                    external_connections[external_ip].add(connection_string)
                    
        except Exception as e:
            if not recent_only:
                log_message(f"Error reading log file: {str(e)}")
        
        return external_connections

    def _parse_log_line_with_connection(self, line):
        """Parse a single log line and return external IP with full connection details"""
        try:
            # Extract CSV data after syslog header
            if '] ' not in line:
                return None
            
            csv_part = line.split('] ', 1)[1]
            fields = csv_part.split(',')
            
            if len(fields) < 22:  # Need at least 22 fields for ports
                return None
            
            action = fields[6].strip() if len(fields) > 6 else ''
            ip_version = fields[8].strip() if len(fields) > 8 else ''
            
            # Only IPv4
            if ip_version != '4':
                return None
            
            # Skip blocked if configured
            if self.config['ignore_blocked_connections'] and action.lower() == 'block':
                return None
            
            # Parse protocol and skip ignored protocols
            protocol_num = 0
            if len(fields) > 15:
                try:
                    protocol_num = int(fields[15].strip()) if fields[15].strip() else 0
                    proto_name = self._get_protocol_name(protocol_num)
                    
                    if proto_name and proto_name.lower() in [p.lower() for p in self.config['ignore_protocols']]:
                        return None
                except (ValueError, IndexError):
                    pass
            
            # Get source and destination IPs and ports
            src_ip = fields[18].strip() if len(fields) > 18 else ''
            dst_ip = fields[19].strip() if len(fields) > 19 else ''
            src_port = fields[20].strip() if len(fields) > 20 else ''
            dst_port = fields[21].strip() if len(fields) > 21 else ''
            
            
            if not src_ip or not dst_ip:
                return None
            
            # Validate external→internal
            external_ip = self._validate_external_to_internal(src_ip, dst_ip)
            if external_ip:
                # Create connection string: SourceIP:Port -> DestIP:Port
                src_port_str = src_port if src_port and src_port.isdigit() else 'unknown'
                dst_port_str = dst_port if dst_port and dst_port.isdigit() else 'unknown'
                
                connection_string = f"{src_ip}:{src_port_str} accessing {dst_ip}:{dst_port_str}"
                
                return {
                    'external_ip': external_ip,
                    'connection_string': connection_string,
                    'protocol': protocol_num,
                    'internal_ip': dst_ip,
                    'internal_port': dst_port_str
                }
            
            return None
            
        except Exception as e:
            log_message(f"Error parsing log line for connections: {str(e)}")
            return None
 
    def _parse_log_line(self, line):
        """Parse a single log line and return external IP if valid"""
        try:
            # Extract CSV data after syslog header
            if '] ' not in line:
                return None
            
            csv_part = line.split('] ', 1)[1]
            fields = csv_part.split(',')
            
            if len(fields) < 20:
                return None
            
            action = fields[6].strip() if len(fields) > 6 else ''
            ip_version = fields[8].strip() if len(fields) > 8 else ''
            
            # Only IPv4
            if ip_version != '4':
                return None
            
            # Skip blocked if configured
            if self.config['ignore_blocked_connections'] and action.lower() == 'block':
                return None
            
            # Parse protocol and skip ignored protocols
            if len(fields) > 15:
                try:
                    proto_num = int(fields[15].strip()) if fields[15].strip() else 0
                    proto_name = self._get_protocol_name(proto_num)
                    
                    if proto_name and proto_name.lower() in [p.lower() for p in self.config['ignore_protocols']]:
                        return None
                except (ValueError, IndexError):
                    pass
            
            # Get source and destination IPs
            src_ip = fields[18].strip() if len(fields) > 18 else ''
            dst_ip = fields[19].strip() if len(fields) > 19 else ''
            
            if not src_ip or not dst_ip:
                return None
            
            return self._validate_external_to_internal(src_ip, dst_ip)
            
        except Exception:
            return None
     
    def _get_protocol_name(self, proto_num):
        """Convert protocol number to name"""
        protocol_map = {1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp'}
        return protocol_map.get(proto_num, '')
    
    def _validate_external_to_internal(self, src_ip, dst_ip):
        """Validate that this is external→internal traffic"""
        try:
            src_ip_obj = ipaddress.ip_address(src_ip)
            dst_ip_obj = ipaddress.ip_address(dst_ip)
            
            # Skip invalid source IPs
            if (src_ip_obj.is_loopback or src_ip_obj.is_multicast or 
                src_ip_obj.is_reserved or src_ip_obj.is_link_local):
                return None
            
            # Check if source IP is external
            src_is_external = not src_ip_obj.is_private
            for network in self.lan_networks:
                if src_ip_obj in network:
                    src_is_external = False
                    break
            
            # Check if destination IP is internal
            dst_is_internal = dst_ip_obj.is_private
            for network in self.lan_networks:
                if dst_ip_obj in network:
                    dst_is_internal = True
                    break
            
            # Only process: External Source → Internal Destination
            if src_is_external and dst_is_internal:
                return src_ip
                
        except ValueError:
            pass
        
        return None
    
    def list_external_to_internal_connections(self):
        """List ALL external→internal connections with detailed info including ports"""
        if not os.path.exists(self.config['log_file']):
            return {'status': 'error', 'message': f"Log file not found: {self.config['log_file']}"}
        
        connections = []
        unique_external_ips = set()
        
        try:
            with open(self.config['log_file'], 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[-500:]  # Last 500 lines for comprehensive view
                
                for line in lines:
                    if 'filterlog' not in line:
                        continue
                    
                    connection_info = self._parse_connection_details(line)
                    if connection_info:
                        connections.append(connection_info)
                        unique_external_ips.add(connection_info['external_ip'])
        
        except Exception as e:
            return {'status': 'error', 'message': f'Error reading log: {str(e)}'}
        
        # Remove duplicates and sort by timestamp
        unique_connections = self._deduplicate_connections(connections)
        
        return {
            'status': 'ok',
            'total_connections': len(unique_connections),
            'unique_external_ips': len(unique_external_ips),
            'connections': unique_connections[:50],  # Show top 50
            'message': f'Found {len(unique_connections)} unique connections from {len(unique_external_ips)} external IPs'
        }
    
    def _parse_connection_details(self, line):
        """Parse detailed connection information from log line including ports"""
        try:
            if '] ' not in line:
                return None
            
            timestamp = line.split(']')[0].replace('[', '').strip()
            csv_part = line.split('] ', 1)[1]
            fields = csv_part.split(',')
            
            if len(fields) < 21:
                return None
            
            action = fields[6].strip()
            ip_version = fields[8].strip()
            protocol = fields[15].strip() if len(fields) > 15 else ''
            
            if ip_version != '4':
                return None
            
            src_ip = fields[18].strip() if len(fields) > 18 else ''
            dst_ip = fields[19].strip() if len(fields) > 19 else ''
            src_port = fields[20].strip() if len(fields) > 20 else ''
            dst_port = fields[21].strip() if len(fields) > 21 else ''
            
            if not src_ip or not dst_ip:
                return None
            
            # Validate external→internal
            if self._validate_external_to_internal(src_ip, dst_ip):
                protocol_name = self._get_protocol_name(int(protocol)) if protocol.isdigit() else protocol
                
                return {
                    'timestamp': timestamp,
                    'external_ip': src_ip,
                    'internal_ip': dst_ip,
                    'external_port': src_port,
                    'internal_port': dst_port,
                    'protocol': protocol_name or protocol,
                    'action': action
                }
                
        except Exception:
            pass
        
        return None
    
    def _deduplicate_connections(self, connections):
        """Remove duplicate connections and sort"""
        unique_connections = []
        seen = set()
        
        for conn in reversed(connections):  # Most recent first
            key = f"{conn['external_ip']}:{conn['internal_ip']}:{conn['internal_port']}:{conn['protocol']}"
            if key not in seen:
                seen.add(key)
                unique_connections.append(conn)
        
        return unique_connections
        """Parse line for debugging purposes with error handling including ports"""
        try:
            if '] ' in line:
                csv_part = line.split('] ', 1)[1]
                fields = csv_part.split(',')
                
                if len(fields) >= 20:
                    return {
                        'action': fields[6].strip(),
                        'direction': fields[7].strip(),
                        'protocol': fields[16].strip() if len(fields) > 16 else '',
                        'src_ip': fields[18].strip(),
                        'dst_ip': fields[19].strip(),
                        'src_port': fields[20].strip() if len(fields) > 20 else '',
                        'dst_port': fields[21].strip() if len(fields) > 21 else ''
                    }
        except Exception as e:
            return {'error': str(e), 'line': line[:100]}
        
        return None