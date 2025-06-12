#!/bin/sh
echo 'Configuring AbuseIPDB Checker...'
mkdir -p /var/log/abuseipdbchecker
mkdir -p /var/db/abuseipdbchecker
chmod 777 /var/log/abuseipdbchecker
chmod 777 /var/db/abuseipdbchecker
/usr/local/opnsense/scripts/AbuseIPDBChecker/setup_database.py
/usr/local/etc/rc.d/configd restart
echo 'AbuseIPDB Checker installed successfully.'