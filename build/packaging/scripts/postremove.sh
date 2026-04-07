#!/bin/bash
systemctl daemon-reload 2>/dev/null || true

# Reload auditd (rules file already removed by package manager)
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load 2>/dev/null || true
fi

# Remove WHM plugin
if [ -x /usr/local/cpanel/bin/unregister_appconfig ]; then
    /usr/local/cpanel/bin/unregister_appconfig csm 2>/dev/null || true
fi
rm -f /usr/local/cpanel/whostmgr/docroot/cgi/addon_csm.cgi 2>/dev/null || true
rm -f /var/cpanel/apps/csm.conf 2>/dev/null || true

# Remove ModSecurity and challenge configs
rm -f /etc/apache2/conf.d/modsec/csm_modsec_custom.conf 2>/dev/null || true
rm -f /etc/apache2/conf.d/csm_challenge.conf 2>/dev/null || true

# Remove PHP Shield ini files
rm -f /opt/cpanel/ea-php*/root/etc/php.d/zzz_csm_shield.ini 2>/dev/null || true

# Clean up runtime files
rm -f /opt/csm/state/.pkg-installed 2>/dev/null || true
rm -rf /var/run/csm 2>/dev/null || true

echo "CSM removed. Config preserved at /opt/csm/csm.yaml (remove manually if desired)."
echo "State data preserved at /opt/csm/state/ (remove manually if desired)."
