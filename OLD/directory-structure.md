# OPNsense AbuseIPDB Plugin Directory Structure

```
abuseipdbchecker/
├── Makefile
├── pkg-descr
├── src/
│   ├── etc/
│   │   └── inc/
│   │       └── plugins.inc.d/
│   │           └── abuseipdbchecker.inc
│   ├── opnsense/
│   │   ├── mvc/
│   │   │   ├── app/
│   │   │   │   ├── controllers/
│   │   │   │   │   └── OPNsense/
│   │   │   │   │       └── AbuseIPDBChecker/
│   │   │   │   │           ├── Api/
│   │   │   │   │           │   └── SettingsController.php
│   │   │   │   │           └── UIController.php
│   │   │   │   ├── models/
│   │   │   │   │   └── OPNsense/
│   │   │   │   │       └── AbuseIPDBChecker/
│   │   │   │   │           ├── AbuseIPDBChecker.php
│   │   │   │   │           └── AbuseIPDBChecker.xml
│   │   │   │   └── views/
│   │   │   │       └── OPNsense/
│   │   │   │           └── AbuseIPDBChecker/
│   │   │   │               └── index.volt
│   │   │   └── resources/
│   │   │       └── views/
│   │   │           └── AbuseIPDBChecker/
│   │   │               └── settings.volt
│   │   ├── scripts/
│   │   │   └── AbuseIPDBChecker/
│   │   │       └── checker.py
│   │   └── service/
│   │       └── conf/
│   │           └── actions.d/
│   │               └── actions_abuseipdbchecker.conf
│   └── rc.d/
│       └── abuseipdbchecker
└── plugin.xml
```

## Files Description

### Main Configuration

1. **plugin.xml** - Plugin manifest file with metadata and installation scripts
2. **Makefile** - Build instructions for the plugin
3. **pkg-descr** - Package description for OPNsense package manager

### Model and Controller

1. **AbuseIPDBChecker.xml** - XML model definition for plugin settings
2. **AbuseIPDBChecker.php** - PHP model class for settings
3. **SettingsController.php** - API controller for AJAX interactions
4. **UIController.php** - UI controller for the webpages

### Views

1. **index.volt** - Main plugin page template
2. **settings.volt** - Settings page template

### Scripts

1. **checker.py** - Main Python script that does the IP checking
2. **abuseipdbchecker.inc** - Plugin integration with OPNsense
3. **abuseipdbchecker** - RC script for service management

### Service Configuration

1. **actions_abuseipdbchecker.conf** - ConfigD actions registration
