#!/bin/bash
set -e

CONFIG="/opt/csm/csm.yaml"
LEGACY_MARKER="/opt/csm/state/.pkg-installed"
MARKER="/var/lib/csm/.pkg-installed"

# Detect fresh install vs upgrade
IS_UPGRADE=0
if [ "${1:-}" = "2" ]; then
    IS_UPGRADE=1                         # RPM upgrade
elif [ "${1:-}" = "configure" ] && { [ -f "$MARKER" ] || [ -f "$LEGACY_MARKER" ]; }; then
    IS_UPGRADE=1                         # DEB upgrade
fi

# Ensure FHS dirs exist (defense in depth; nfpm should have created them).
install -d -m 0750 /etc/csm /etc/csm/conf.d
install -d -m 0700 /var/lib/csm /var/lib/csm/state
install -d -m 0755 /usr/lib/csm /usr/lib/csm/profiles

# Auto-detect hostname (unchanged from prior behaviour)
if grep -q 'SET_HOSTNAME_HERE' "$CONFIG" 2>/dev/null; then
    DETECTED=""
    [ -f /etc/hostname ] && DETECTED=$(cat /etc/hostname | tr -d '[:space:]')
    [ -z "$DETECTED" ] && DETECTED=$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)
    if [ -n "$DETECTED" ] && [ "$DETECTED" != "localhost" ]; then
        sed -i "s/SET_HOSTNAME_HERE/${DETECTED}/g" "$CONFIG"
        echo "Auto-detected hostname: ${DETECTED}"
    fi
fi

# Auto-detect admin email (unchanged)
if grep -q 'SET_EMAIL_HERE' "$CONFIG" 2>/dev/null; then
    DETECTED=""
    if [ -f /var/cpanel/cpanel.config ]; then
        DETECTED=$(grep '^contactemail=' /var/cpanel/cpanel.config 2>/dev/null | cut -d= -f2)
    fi
    [ -z "$DETECTED" ] && DETECTED="root@$(hostname -f 2>/dev/null || hostname)"
    if [ -n "$DETECTED" ]; then
        sed -i "s/SET_EMAIL_HERE/${DETECTED}/g" "$CONFIG"
        echo "Auto-detected email: ${DETECTED}"
    fi
fi

# Generate WebUI auth token (unchanged)
if grep -q 'auth_token: ""' "$CONFIG" 2>/dev/null; then
    TOKEN=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)
    sed -i "s/auth_token: \"\"/auth_token: \"${TOKEN}\"/" "$CONFIG"
    echo "Generated WebUI auth token (saved in csm.yaml)"
fi

# Upgrade hygiene: remove obsolete tier timers (unchanged)
for unit in csm-critical.timer csm-critical.service csm-deep.timer csm-deep.service; do
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
    rm -f "/etc/systemd/system/$unit"
done

systemctl daemon-reload 2>/dev/null || true

if [ "$IS_UPGRADE" = "0" ]; then
    /opt/csm/csm install --package-mode 2>/dev/null || true
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load 2>/dev/null || true
    fi
    /opt/csm/csm validate 2>/dev/null || echo "WARNING: Config has issues. Run: /opt/csm/csm validate"
    chattr +i /opt/csm/csm 2>/dev/null || true
    echo ""
    echo "=== CSM installed ==="
    echo "  Config:       /opt/csm/csm.yaml"
    echo "  Drop-ins:     /etc/csm/conf.d/*.yaml"
    echo "  State:        /var/lib/csm/state/"
    echo "  Profiles:     /usr/lib/csm/profiles/"
    echo "  WebUI:        https://$(hostname -f 2>/dev/null || hostname):9443/"
    echo ""
    echo "Next steps:"
    echo "  1. Review config:   vi /opt/csm/csm.yaml"
    echo "  2. Set baseline:    /opt/csm/csm baseline"
    echo "  3. Start daemon:    systemctl enable --now csm.service"
else
    chattr -i /opt/csm/csm 2>/dev/null || true
    chattr +i /opt/csm/csm 2>/dev/null || true
    /opt/csm/csm rehash 2>/dev/null || true
    if systemctl is-active --quiet csm.service 2>/dev/null; then
        systemctl restart csm.service
        echo "CSM upgraded and restarted (state will migrate on first run if needed)"
    else
        echo "CSM upgraded (daemon not running; start with: systemctl start csm.service)"
    fi
fi

# Marker (kept under /var/lib for the future; legacy marker preserved on upgraded hosts)
touch "$MARKER"
