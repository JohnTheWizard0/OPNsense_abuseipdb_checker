#!/usr/bin/env python3
# build/generate-manifest.py - Auto-generates package manifest

import os
import json
import hashlib
import argparse
from pathlib import Path

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def scan_files(build_dir):
    """Scan build directory and generate file manifest"""
    files_dict = {}
    build_path = Path(build_dir)
    
    for file_path in build_path.rglob("*"):
        if file_path.is_file():
            # Get relative path from build_dir
            rel_path = file_path.relative_to(build_path)
            # Convert to absolute installation path
            install_path = f"/{rel_path}"
            # Calculate file hash
            file_hash = calculate_sha256(file_path)
            files_dict[install_path] = file_hash
    
    return files_dict

def generate_manifest(name, version, build_dir, output_file):
    """Generate complete package manifest"""
    
    # Scan files
    files = scan_files(build_dir)
    
    # Define dependencies based on your plugin requirements
    dependencies = {
        "php82": {"origin": "lang/php82", "version": "8.2.*"},
        "py39-requests": {"origin": "www/py-requests", "version": "2.*"},
        "sqlite3": {"origin": "databases/sqlite3", "version": "3.*"}
    }
    
    # Create manifest
    manifest = {
        "name": name,
        "version": version,
        "origin": f"security/{name.replace('os-', '')}",
        "comment": "AbuseIPDB IP reputation checker for OPNsense",
        "desc": "Monitors external IP addresses attempting to connect to internal networks and checks them against AbuseIPDB reputation database to identify potential threats.",
        "maintainer": "wizard@hekate.dev",
        "www": "https://github.com/JohnTheWizard0/OPNsense_abuseipdb_checker",
        "arch": "freebsd:*",
        "prefix": "/usr/local",
        "flatsize": sum(os.path.getsize(Path(build_dir) / Path(f).relative_to('/')) 
                       for f in files.keys() if Path(build_dir) / Path(f).relative_to('/') != Path(build_dir)),
        "licenselogic": "single",
        "licenses": ["BSD-2-Clause"],
        "deps": dependencies,
        "files": files,
        "scripts": {
            "post-install": [
                "echo 'Configuring AbuseIPDB Checker...'",
                "mkdir -p /var/log/abuseipdbchecker",
                "mkdir -p /var/db/abuseipdbchecker",
                "chmod 777 /var/log/abuseipdbchecker",
                "chmod 777 /var/db/abuseipdbchecker",
                "/usr/local/opnsense/scripts/AbuseIPDBChecker/setup_database.py",
                "/usr/local/etc/rc.d/configd restart",
                "echo 'AbuseIPDB Checker installed successfully.'"
            ],
            "post-deinstall": [
                "echo 'Cleaning up AbuseIPDB Checker...'",
                "/usr/local/etc/rc.d/configd restart"
            ]
        },
        "annotations": {
            "repo_type": "binary",
            "repository": "AbuseIPDBChecker"
        },
        "messages": [
            {
                "message": f"""
AbuseIPDB Checker v{version} has been installed successfully!

CONFIGURATION STEPS:
1. Navigate to Services → AbuseIPDB Checker
2. Configure your AbuseIPDB API key
3. Set checking intervals and thresholds
4. Enable the service

DOCUMENTATION:
https://github.com/JohnTheWizard0/OPNsense_abuseipdb_checker

For support, please visit the GitHub repository.
""".strip()
            }
        ]
    }
    
    # Write manifest
    with open(output_file, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"✓ Generated manifest with {len(files)} files")
    print(f"✓ Package size: {manifest['flatsize']} bytes")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate OPNsense plugin manifest')
    parser.add_argument('--name', required=True, help='Package name')
    parser.add_argument('--version', required=True, help='Package version')
    parser.add_argument('--build-dir', required=True, help='Build directory')
    parser.add_argument('--output', required=True, help='Output manifest file')
    
    args = parser.parse_args()
    generate_manifest(args.name, args.version, args.build_dir, args.output)