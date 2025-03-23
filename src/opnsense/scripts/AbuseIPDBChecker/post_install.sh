#!/bin/sh

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

echo "AbuseIPDBChecker post-installation completed"