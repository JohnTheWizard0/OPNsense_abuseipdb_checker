# AbuseIPDB Checker - Installation Guide

## Installation Methods

### Method 1: One-Line Install (Recommended)
```bash
curl -sSL https://raw.githubusercontent.com/JohnTheWizard0/OPNsense_abuseipdb_checker/main/install.sh | sh
```

### Method 2: Repository Install
```bash
# Add repository
fetch -o /usr/local/etc/pkg/repos/abuseipdbchecker.conf \
  https://raw.githubusercontent.com/JohnTheWizard0/OPNsense_abuseipdb_checker/main/repository.conf

# Install plugin
pkg update
pkg install os-abuseipdbchecker
```

### Method 3: Direct Package Install
```bash
# Download latest release
fetch https://github.com/JohnTheWizard0/OPNsense_abuseipdb_checker/releases/latest/download/os-abuseipdbchecker-latest.pkg

# Install package
pkg add os-abuseipdbchecker-latest.pkg
```

## Post-Installation Configuration

1. **Access Plugin Interface**
   - Navigate to `Services` → `AbuseIPDB Checker`

2. **Configure API Settings**
   - Enter your AbuseIPDB API key
   - Set API endpoint (default: https://api.abuseipdb.com/api/v2/check)
   - Configure daily check limits

3. **Network Configuration**
   - Define LAN subnets to monitor
   - Set protocols to ignore (ICMP, IGMP)

4. **Alias Configuration**
   - Enable automatic alias updates
   - Configure OPNsense API credentials
   - Set maximum hosts in alias

5. **Start Service**
   - Go to `Services` → `AbuseIPDB Checker`
   - Click `Start` to begin monitoring

## Verification

Check service status:
```bash
# Check if service is running
/usr/local/etc/rc.d/abuseipdbchecker status

# View logs
tail -f /var/log/abuseipdbchecker/abuseipdb.log
```

## Troubleshooting

### Plugin Shows as "Misconfigured"
- Ensure all dependencies are installed
- Check `/tmp/PHP_errors.log` for errors
- Restart configd: `/usr/local/etc/rc.d/configd restart`

### Service Won't Start
- Verify API key configuration
- Check file permissions in `/var/log/abuseipdbchecker/`
- Initialize database: `/usr/local/opnsense/scripts/AbuseIPDBChecker/setup_database.py`

### Repository Issues
- Clear package cache: `pkg clean -a`
- Update repositories: `pkg update -f`
- Check repository configuration in `/usr/local/etc/pkg/repos/`

## Uninstallation

```bash
# Stop service
/usr/local/etc/rc.d/abuseipdbchecker stop

# Remove package
pkg delete os-abuseipdbchecker

# Remove repository (optional)
rm /usr/local/etc/pkg/repos/abuseipdbchecker.conf

# Clean up data (optional)
rm -rf /var/log/abuseipdbchecker
rm -rf /var/db/abuseipdbchecker
```

## Support

- **Documentation**: https://github.com/JohnTheWizard0/OPNsense_abuseipdb_checker
- **Issues**: https://github.com/JohnTheWizard0/OPNsense_abuseipdb_checker/issues
- **API Documentation**: https://docs.abuseipdb.com/