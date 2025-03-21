# OPNsense AbuseIPDB Plugin - Installation and Usage Guide

This guide explains how to install, configure, and use the AbuseIPDB Checker plugin for OPNsense firewalls.

## Features

- Monitor external IPs attempting to connect to your LAN subnets
- Check suspicious IPs against AbuseIPDB's reputation database
- Includes connection port information in alerts
- Configurable protocol filtering
- Option to focus only on allowed connections
- Daily API check limits to manage usage
- Weekly IP rechecking to avoid duplicate lookups
- Email notifications for potential threats

## Installation

### Method 1: Manual Installation

1. **Create the plugin directory structure**

   Follow the directory structure provided in the `directory-structure.md` file to set up all necessary files.

2. **Clone the repository (if available)**

   ```bash
   git clone https://github.com/yourusername/opnsense-abuseipdb-plugin.git
   cd opnsense-abuseipdb-plugin
   ```

3. **Copy files to OPNsense**

   Create a package or manually copy the files to the appropriate locations on your OPNsense firewall.

4. **Install dependencies**

   ```bash
   pkg install -y py38-requests py38-sqlite3
   ```

5. **Set up the service**

   ```bash
   chmod +x /usr/local/opnsense/scripts/AbuseIPDBChecker/checker.py
   chmod +x /usr/local/etc/rc.d/abuseipdbchecker
   ```

6. **Enable the service**

   ```bash
   echo 'abuseipdbchecker_enable="YES"' >> /etc/rc.conf.local
   service abuseipdbchecker start
   ```

### Method 2: OPNsense Package Manager (once published)

1. System → Firmware → Plugins
2. Search for "AbuseIPDB"
3. Click the "+" button to install

## Configuration

1. **Access the plugin**

   Navigate to **Firewall → AbuseIPDBChecker** in the OPNsense web interface.

2. **General Settings**

   - **Enable Plugin**: Turn the plugin on/off
   - **Check Frequency**: How many days to wait before rechecking an IP
   - **Abuse Score Threshold**: Minimum confidence score (1-100) to consider an IP a threat
   - **Daily Check Limit**: Maximum number of IPs to check per day
   - **Ignore Blocked Connections**: Only monitor allowed connections

3. **Network Settings**

   - **LAN Subnets**: Comma-separated list of your internal networks in CIDR notation
   - **Ignore Protocols**: Protocols to exclude from monitoring (e.g., icmp,igmp)

4. **AbuseIPDB API Settings**

   - **API Key**: Your AbuseIPDB API key ([sign up here](https://www.abuseipdb.com/))
   - **Max Age**: How far back to look for reports (in days)

5. **Email Notification Settings**

   - Configure your SMTP server details for email alerts

6. **Save your settings**

   Click the "Save" button to apply your configuration.

## Usage

### Manual Check

You can manually trigger an IP check by clicking the "Run Now" button in the web interface.

### Viewing Threats

The "Recent Threats" tab shows IPs that have been flagged as potential threats based on your threshold setting.

### Statistics

The "Statistics" tab provides information about:
- Total IPs checked
- Total threats detected
- Checks performed today
- Last time the checker ran

## Logs

Check the log file for detailed operation information:

```bash
tail -f /var/log/abuseipdb_checker.log
```

## Troubleshooting

### API Key Issues

If you receive errors about invalid API keys:
1. Verify your API key is correct
2. Check your AbuseIPDB account for API usage limits

### Database Issues

If the database becomes corrupted:

```bash
rm /var/db/abuseipdb_checker.db
service abuseipdbchecker restart
```

### Service Not Starting

Check the status and logs:

```bash
service abuseipdbchecker status
tail -f /var/log/abuseipdb_checker.log
```

## Customization

The plugin can be customized by directly editing the Python script:

```bash
vi /usr/local/opnsense/scripts/AbuseIPDBChecker/checker.py
```

Remember to restart the service after any modifications:

```bash
service abuseipdbchecker restart
```

## Uninstallation

If installed via package manager:

1. System → Firmware → Plugins
2. Find "AbuseIPDB Checker" and click the "-" button

For manual installations:

```bash
service abuseipdbchecker stop
rm -rf /usr/local/opnsense/scripts/AbuseIPDBChecker
rm -f /usr/local/etc/rc.d/abuseipdbchecker
rm -f /usr/local/etc/abuseipdb_checker.conf
rm -f /usr/local/etc/cron.d/abuseipdbchecker
rm -f /var/db/abuseipdb_checker.db
```
