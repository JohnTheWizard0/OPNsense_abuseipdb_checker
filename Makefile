PLUGIN_NAME=		abuseipdbchecker
PLUGIN_VERSION=		1.0
PLUGIN_COMMENT=		AbuseIPDB IP reputation checker
PLUGIN_MAINTAINER=	your.email@example.com
PLUGIN_WWW=		https://github.com/yourusername/opnsense-abuseipdbchecker

.include "../../Mk/plugins.mk"

post-install:
	@echo "Installing post-install script"
	${INSTALL_SCRIPT} ${WRKSRC}/src/opnsense/scripts/AbuseIPDBChecker/post_install.sh ${STAGEDIR}${PREFIX}/opnsense/scripts/AbuseIPDBChecker/
	@echo "Making scripts executable"
	@chmod +x ${STAGEDIR}${PREFIX}/opnsense/scripts/AbuseIPDBChecker/*.py
	@chmod +x ${STAGEDIR}${PREFIX}/opnsense/scripts/AbuseIPDBChecker/*.sh
	@echo "Installing rc script"
	${INSTALL_SCRIPT} ${WRKSRC}/src/etc/rc.d/abuseipdbchecker ${STAGEDIR}${PREFIX}/etc/rc.d/
	@chmod +x ${STAGEDIR}${PREFIX}/etc/rc.d/abuseipdbchecker