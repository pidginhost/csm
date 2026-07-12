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

remove_csm_modsec_sections() {
    local path="$1" tmp mode
    [ -f "$path" ] || return 0
    tmp=$(mktemp "${path}.csm-remove.XXXXXX") || return 1
    mode=$(stat -c '%a' "$path" 2>/dev/null) || mode=$(stat -f '%Lp' "$path" 2>/dev/null) || { rm -f "$tmp"; return 1; }
    if ! awk '
        BEGIN { managed = 0; skip_include = 0 }
        managed {
            if ($0 == "# END CSM Custom ModSecurity Rules") { managed = 0; next }
            if ($0 == "# CSM overrides - managed by CSM rule management") { managed = 0 }
            else { next }
        }
        $0 == "# BEGIN CSM Custom ModSecurity Rules (managed by CSM - do not edit inside this block)" { managed = 1; next }
        $0 == "# CSM Custom ModSecurity Rules" { managed = 1; next }
        $0 == "# CSM overrides - managed by CSM rule management" { skip_include = 1; next }
        skip_include && $0 ~ /^[[:space:]]*Include[[:space:]].*modsec2[.]csm-overrides[.]conf[[:space:]]*$/ { skip_include = 0; next }
        { skip_include = 0; print }
    ' "$path" > "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    chmod "$mode" "$tmp" || { rm -f "$tmp"; return 1; }
    if grep -q '[^[:space:]]' "$tmp"; then
        mv -f "$tmp" "$path"
    else
        rm -f "$tmp" "$path"
    fi
}

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

# Remove CSM's sections from shared ModSecurity user files. Delete the
# overrides only after the include was removed successfully.
for user_conf in /etc/apache2/conf.d/modsec/modsec2.user.conf /usr/local/apache/conf/modsec2.user.conf; do
    if remove_csm_modsec_sections "$user_conf"; then
        rm -f "$(dirname "$user_conf")/modsec2.csm-overrides.conf" 2>/dev/null || true
    else
        echo "WARNING: could not remove CSM ModSecurity rules from $user_conf" >&2
    fi
done
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
