#!/bin/bash
# Post-removal hook.
#
# rpm passes $1=0 on full uninstall and $1=1 on upgrade-leftover. deb passes
# "remove" / "purge" / "upgrade". On upgrade the old package's postremove
# runs AFTER the new package's postinstall, so deleting plugin files, audit
# rules, the install marker, and announcing "CSM removed" would corrupt the
# freshly-installed version.
if [ "${1:-}" = "1" ] || [ "${1:-}" = "upgrade" ]; then
    exit 0
fi

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
rm -f /var/lib/csm/.pkg-installed 2>/dev/null || true
rm -rf /var/run/csm 2>/dev/null || true

echo "CSM removed. Config preserved at /etc/csm/csm.yaml (remove manually if desired)."
echo "State data preserved at /var/lib/csm/state/ (remove manually if desired)."
