<?php
namespace OPNsense\AbuseIPDBChecker\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;

class SettingsController extends ApiControllerBase
{
    public function getAction()
    {
        // Direct file reading approach
        $config_file = '/usr/local/etc/abuseipdbchecker/abuseipdbchecker.conf';
        $settings = [];
        
        if (file_exists($config_file)) {
            $ini_content = parse_ini_file($config_file, true);
            if ($ini_content !== false) {
                $settings = $ini_content;
            }
        }
        
        // Default values if file doesn't exist or is empty
        if (empty($settings)) {
            $settings = [
                'general' => [
                    'Enabled' => '1',
                    'LogFile' => '/var/log/filter.log',
                    'CheckFrequency' => '7',
                    'AbuseScoreThreshold' => '80',
                    'DailyCheckLimit' => '100',
                    'IgnoreBlockedConnections' => '1'
                ],
                'network' => [
                    'LanSubnets' => '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12',
                    'IgnoreProtocols' => 'icmp,igmp'
                ],
                'api' => [
                    'Key' => 'YOUR_API_KEY',
                    'Endpoint' => 'https://api.abuseipdb.com/api/v2/check',
                    'MaxAge' => '90'
                ],
                'email' => [
                    'Enabled' => '0',
                    'SmtpServer' => 'smtp.example.com',
                    'SmtpPort' => '587',
                    'SmtpUsername' => '',
                    'SmtpPassword' => '',
                    'FromAddress' => 'firewall@yourdomain.com',
                    'ToAddress' => 'admin@yourdomain.com',
                    'UseTLS' => '1'
                ]
            ];
        }
        
        return ['abuseipdbchecker' => $settings];
    }
    
    public function setAction()
    {
        $result = ['result' => 'failed'];
        
        if ($this->request->isPost()) {
            $config_dir = '/usr/local/etc/abuseipdbchecker';
            $config_file = $config_dir . '/abuseipdbchecker.conf';
            
            // Create directory if needed
            if (!file_exists($config_dir)) {
                mkdir($config_dir, 0755, true);
            }
            
            // Get POST data
            $data = $this->request->getPost('abuseipdbchecker');
            if (!empty($data)) {
                // Write to file
                $content = "";
                
                foreach ($data as $section => $settings) {
                    $content .= "[$section]\n";
                    
                    foreach ($settings as $key => $value) {
                        // Handle boolean values
                        if ($value === true || $value === 'true' || $value === '1') {
                            $value = '1';
                        } elseif ($value === false || $value === 'false' || $value === '0') {
                            $value = '0';
                        }
                        
                        $content .= "$key=$value\n";
                    }
                    
                    $content .= "\n";
                }
                
                // Write content to file
                $success = file_put_contents($config_file, $content);
                
                if ($success !== false) {
                    $result['result'] = 'saved';
                }
            }
        }
        
        return $result;
    }
}