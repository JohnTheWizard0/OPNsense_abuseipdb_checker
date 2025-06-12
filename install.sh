#!/bin/bash
# install.sh - One-line installer for AbuseIPDB Checker

set -e

REPO_CONF="/usr/local/etc/pkg/repos/abuseipdbchecker.conf"
REPO_URL="https://raw.githubusercontent.com/JohnTheWizard0/OPNsense_abuseipdb_checker/main/repository.conf"
PACKAGE_NAME="os-abuseipdbchecker"

echo "=========================================="
echo "AbuseIPDB Checker - OPNsense Plugin Installer"
echo "=========================================="

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

# Check if OPNsense
if [ ! -f "/usr/local/opnsense/version/core" ]; then
    echo "❌ This installer is for OPNsense only"
    exit 1
fi

echo "✓ Running on OPNsense as root"

# Add repository
echo "Adding AbuseIPDB Checker repository..."
fetch -o "$REPO_CONF" "$REPO_URL"
if [ $? -eq 0 ]; then
    echo "✓ Repository configuration added"
else
    echo "❌ Failed to add repository"
    exit 1
fi

# Update package database
echo "Updating package database..."
pkg update
if [ $? -eq 0 ]; then
    echo "✓ Package database updated"
else
    echo "❌ Failed to update package database"
    exit 1
fi

# Install plugin
echo "Installing AbuseIPDB Checker plugin..."
pkg install -y "$PACKAGE_NAME"
if [ $? -eq 0 ]; then
    echo "✓ Plugin installed successfully"
else
    echo "❌ Failed to install plugin"
    exit 1
fi

echo "=========================================="
echo "🎉 Installation completed successfully!"
echo ""
echo "NEXT STEPS:"
echo "1. Open OPNsense web interface"
echo "2. Go to Services → AbuseIPDB Checker"
echo "3. Enter your AbuseIPDB API key"
echo "4. Configure settings and enable service"
echo ""
echo "DOCUMENTATION:"
echo "https://github.com/JohnTheWizard0/OPNsense_abuseipdb_checker"
echo "=========================================="