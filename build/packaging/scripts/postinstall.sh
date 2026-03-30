#!/bin/bash
set -e

CONFIG="/opt/csm/csm.yaml"
MARKER="/opt/csm/state/.pkg-installed"

# Detect fresh install vs upgrade
IS_UPGRADE=0
if [ "${1:-}" = "2" ]; then
    # RPM upgrade
    IS_UPGRADE=1
elif [ "${1:-}" = "configure" ] && [ -f "$MARKER" ]; then
    # DEB upgrade
    IS_UPGRADE=1
fi

# Auto-detect hostname
if grep -q 'SET_HOSTNAME_HERE' "$CONFIG" 2>/dev/null; then
    DETECTED=""
    [ -f /etc/hostname ] && DETECTED=$(cat /etc/hostname | tr -d '[:space:]')
    [ -z "$DETECTED" ] && DETECTED=$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)
    if [ -n "$DETECTED" ] && [ "$DETECTED" != "localhost" ]; then
        sed -i "s/SET_HOSTNAME_HERE/${DETECTED}/g" "$CONFIG"
        echo "Auto-detected hostname: ${DETECTED}"
    fi
fi

# Auto-detect admin email from cPanel
if grep -q 'SET_EMAIL_HERE' "$CONFIG" 2>/dev/null; then
    DETECTED=""
    if [ -f /var/cpanel/cpanel.config ]; then
        DETECTED=$(grep '^contactemail=' /var/cpanel/cpanel.config 2>/dev/null | cut -d= -f2)
    fi
    if [ -z "$DETECTED" ]; then
        DETECTED="root@$(hostname -f 2>/dev/null || hostname)"
    fi
    if [ -n "$DETECTED" ]; then
        sed -i "s/SET_EMAIL_HERE/${DETECTED}/g" "$CONFIG"
        echo "Auto-detected email: ${DETECTED}"
    fi
fi

# Generate random WebUI auth token if not set
if grep -q 'auth_token: ""' "$CONFIG" 2>/dev/null; then
    TOKEN=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)
    sed -i "s/auth_token: \"\"/auth_token: \"${TOKEN}\"/" "$CONFIG"
    echo "Generated WebUI auth token (saved in csm.yaml)"
fi

# Reload systemd
systemctl daemon-reload 2>/dev/null || true

if [ "$IS_UPGRADE" = "0" ]; then
    # Fresh install: run cPanel-specific integration (WHM plugin, ModSecurity, etc.)
    /opt/csm/csm install --package-mode 2>/dev/null || true

    # Enable timers
    systemctl enable csm-critical.timer csm-deep.timer 2>/dev/null || true
    systemctl start csm-critical.timer csm-deep.timer 2>/dev/null || true

    # Load auditd rules
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load 2>/dev/null || true
    fi

    # Validate config
    /opt/csm/csm validate 2>/dev/null || echo "WARNING: Config has issues. Run: /opt/csm/csm validate"

    # Set immutable
    chattr +i /opt/csm/csm 2>/dev/null || true

    echo ""
    echo "=== CSM installed ==="
    echo "  Config: /opt/csm/csm.yaml"
    echo "  WebUI:  https://$(hostname -f 2>/dev/null || hostname):9443/"
    echo ""
    echo "Next steps:"
    echo "  1. Review config:   vi /opt/csm/csm.yaml"
    echo "  2. Set baseline:    /opt/csm/csm baseline"
    echo "  3. Start daemon:    systemctl enable --now csm.service"
else
    # Upgrade: rehash and restart
    chattr -i /opt/csm/csm 2>/dev/null || true
    chattr +i /opt/csm/csm 2>/dev/null || true
    /opt/csm/csm rehash 2>/dev/null || true
    /opt/csm/csm rehash 2>/dev/null || true
    if systemctl is-active --quiet csm.service 2>/dev/null; then
        systemctl restart csm.service
        echo "CSM upgraded and restarted"
    else
        echo "CSM upgraded (daemon not running — start with: systemctl start csm.service)"
    fi
fi

# Mark as installed for upgrade detection
mkdir -p /opt/csm/state
touch "$MARKER"
