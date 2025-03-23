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

mkdir -p /var/log/abuseipdbchecker
chmod -R 755 /var/log/abuseipdbchecker
chown -R www:www /var/log/abuseipdbchecker

mkdir -p /var/db/abuseipdbchecker
chmod -R 755 /var/db/abuseipdbchecker
chown -R www:www /var/db/abuseipdbchecker

mkdir -p /usr/local/etc/abuseipdbchecker
chmod -R 755 /usr/local/etc/abuseipdbchecker

chmod 755 /usr/local/opnsense/scripts/AbuseIPDBChecker/checker.py
chmod 755 /usr/local/opnsense/scripts/AbuseIPDBChecker/setup_database.py

mkdir -p /usr/local/opnsense/scripts/OPNsense
ln -sf /usr/local/opnsense/scripts/AbuseIPDBChecker /usr/local/opnsense/scripts/OPNsense/

touch /var/log/abuseipdbchecker/abuseipdb.log
chmod -R 777 /var/log/abuseipdbchecker
chown -R www:www /var/log/abuseipdbchecker

echo "abuseipdbchecker_enable=\"YES\"" >> /etc/rc.conf.local
echo "AbuseIPDBChecker post-installation completed"