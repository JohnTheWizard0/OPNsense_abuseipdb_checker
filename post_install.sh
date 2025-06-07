#!/bin/sh

WRKSRC="/usr/ports/opnsense/security/abuseipdbchecker/work/src"
STAGEDIR="/"
PREFIX="/usr/local"

echo "Installing rc script"
install -m 755 "${WRKSRC}/usr/local/etc/rc.d/abuseipdbchecker" \
  "${PREFIX}/etc/rc.d/"

chmod 755 /usr/local/etc/rc.d/abuseipdbchecker

echo "Installing plugin registration file"
install -m 644 "${WRKSRC}/usr/local/etc/inc/plugins.inc.d/abuseipdbchecker.inc" \
  "${PREFIX}/etc/inc/plugins.inc.d/"

# Create directories with proper permissions
mkdir -p /var/log/abuseipdbchecker
chmod 777 /var/log/abuseipdbchecker

mkdir -p /var/db/abuseipdbchecker  
chmod 777 /var/db/abuseipdbchecker

mkdir -p /usr/local/etc/abuseipdbchecker
chmod 755 /usr/local/etc/abuseipdbchecker

# Make scripts executable
chmod 755 /usr/local/opnsense/scripts/AbuseIPDBChecker/checker.py
chmod 755 /usr/local/opnsense/scripts/AbuseIPDBChecker/setup_database.py
chmod 755 /usr/local/opnsense/scripts/AbuseIPDBChecker/manage_alias.py

# Create symlink for OPNsense script path
mkdir -p /usr/local/opnsense/scripts/OPNsense
ln -sf /usr/local/opnsense/scripts/AbuseIPDBChecker /usr/local/opnsense/scripts/OPNsense/

# Initialize log file
touch /var/log/abuseipdbchecker/abuseipdb.log
chmod 666 /var/log/abuseipdbchecker/abuseipdb.log

# Kill any existing processes before enabling
pkill -f "checker.py daemon" 2>/dev/null || true
rm -f /var/run/abuseipdbchecker.pid 2>/dev/null || true

# Enable the service
echo "abuseipdbchecker_enable=\"YES\"" >> /etc/rc.conf.local

echo "AbuseIPDBChecker post-installation completed"