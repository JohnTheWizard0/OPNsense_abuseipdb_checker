#!/usr/local/bin/python3

"""
AbuseIPDB API Client Module
Handles all interactions with the AbuseIPDB API
"""

import requests
import time
from .core_utils import log_message

class AbuseIPDBClient:
    """Centralized AbuseIPDB API client with error handling and rate limiting"""
    
    def __init__(self, config):
        self.config = config
        self.api_key = config['api_key']
        self.api_endpoint = config['api_endpoint']
        self.max_age = config['max_age']
        self.last_request_time = 0
        self.min_request_interval = 0.5  # Minimum 500ms between requests
    
    def check_ip(self, ip_address):
        """Check a single IP against AbuseIPDB API with proper error handling"""
        if not self._validate_api_config():
            raise Exception("API configuration invalid")
        
        # Rate limiting
        self._enforce_rate_limit()
        
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': self.max_age
        }
        
        try:
            log_message(f"API Request: Checking {ip_address}")
            
            response = requests.get(
                self.api_endpoint, 
                headers=headers, 
                params=params,
                timeout=10
            )
            
            self.last_request_time = time.time()
            
            log_message(f"API Response: HTTP {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                report_data = data.get('data', {})
                log_message(f"API Success: {ip_address} scored {report_data.get('abuseConfidenceScore', 0)}%")
                return report_data
                
            elif response.status_code == 401:
                error_msg = "Authentication failed - invalid API key"
                log_message(f"API Error 401: {error_msg}")
                raise APIAuthenticationError(error_msg)
                
            elif response.status_code == 429:
                error_msg = "Rate limit exceeded"
                log_message(f"API Error 429: {error_msg}")
                raise APIRateLimitError(error_msg)
                
            elif response.status_code == 422:
                error_msg = f"Invalid IP address: {ip_address}"
                log_message(f"API Error 422: {error_msg}")
                raise APIValidationError(error_msg)
                
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                log_message(f"API Error {response.status_code}: {response.text}")
                raise APIRequestError(error_msg)
                
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {str(e)}"
            log_message(f"API Connection Error: {error_msg}")
            raise APIConnectionError(error_msg)
            
        except requests.exceptions.Timeout as e:
            error_msg = f"Request timeout: {str(e)}"
            log_message(f"API Timeout: {error_msg}")
            raise APITimeoutError(error_msg)
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Request error: {str(e)}"
            log_message(f"API Request Error: {error_msg}")
            raise APIRequestError(error_msg)
    
    def batch_check_ips(self, ip_list, max_checks=None):
        """Check multiple IPs with built-in rate limiting and error handling"""
        if not self._validate_api_config():
            raise Exception("API configuration invalid")
        
        results = {}
        checks_performed = 0
        max_checks = max_checks or len(ip_list)
        
        for ip in ip_list:
            if checks_performed >= max_checks:
                log_message(f"Batch check limit reached: {checks_performed}/{max_checks}")
                break
            
            try:
                result = self.check_ip(ip)
                results[ip] = {
                    'status': 'success',
                    'data': result
                }
                checks_performed += 1
                
            except APIRateLimitError as e:
                log_message(f"Rate limit hit during batch check at IP {ip}")
                results[ip] = {
                    'status': 'rate_limited',
                    'error': str(e)
                }
                break  # Stop batch on rate limit
                
            except (APIAuthenticationError, APIConnectionError) as e:
                log_message(f"Critical API error during batch check: {str(e)}")
                results[ip] = {
                    'status': 'critical_error',
                    'error': str(e)
                }
                break  # Stop batch on critical errors
                
            except Exception as e:
                log_message(f"Error checking IP {ip} in batch: {str(e)}")
                results[ip] = {
                    'status': 'error',
                    'error': str(e)
                }
                continue  # Continue batch on individual IP errors
        
        return {
            'results': results,
            'checks_performed': checks_performed,
            'total_requested': len(ip_list)
        }
    
    def test_connection(self):
        """Test API connectivity and authentication"""
        test_ip = "8.8.8.8"  # Google DNS - safe test IP
        
        try:
            result = self.check_ip(test_ip)
            return {
                'status': 'success',
                'message': 'API connection successful',
                'test_ip': test_ip,
                'response': result
            }
        except APIAuthenticationError:
            return {
                'status': 'auth_error',
                'message': 'API key authentication failed'
            }
        except APIConnectionError:
            return {
                'status': 'connection_error',
                'message': 'Unable to connect to AbuseIPDB API'
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'API test failed: {str(e)}'
            }
    
    def _validate_api_config(self):
        """Validate API configuration"""
        if not self.api_key:
            log_message("API key not configured")
            return False
        
        if self.api_key == 'YOUR_API_KEY':
            log_message("Default placeholder API key detected")
            return False
        
        if not self.api_endpoint:
            log_message("API endpoint not configured")
            return False
        
        return True
    
    def _enforce_rate_limit(self):
        """Enforce minimum time between API requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
    
    def get_api_status(self):
        """Get current API client status"""
        return {
            'api_key_configured': bool(self.api_key and self.api_key != 'YOUR_API_KEY'),
            'api_endpoint': self.api_endpoint,
            'max_age_days': self.max_age,
            'rate_limit_interval': self.min_request_interval,
            'last_request_time': self.last_request_time
        }

# Custom Exception Classes for better error handling
class APIError(Exception):
    """Base exception for API errors"""
    pass

class APIAuthenticationError(APIError):
    """Raised when API authentication fails"""
    pass

class APIRateLimitError(APIError):
    """Raised when API rate limit is exceeded"""
    pass

class APIConnectionError(APIError):
    """Raised when connection to API fails"""
    pass

class APITimeoutError(APIError):
    """Raised when API request times out"""
    pass

class APIValidationError(APIError):
    """Raised when API request has validation errors"""
    pass

class APIRequestError(APIError):
    """Raised for general API request errors"""
    pass
