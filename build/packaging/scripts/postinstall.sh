#!/bin/bash
set -e

PREFERRED_CONFIG="/etc/csm/csm.yaml"
LEGACY_CONFIG="/opt/csm/csm.yaml"
CONFIG="$PREFERRED_CONFIG"
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

is_placeholder_config() {
    # Only the SET_*_HERE markers are reliable placeholders. The shipped
    # default has both. `auth_token: ""` is a legitimate operator value
    # in v2.11.0+ when the new webui.tokens block replaces the legacy
    # single-token field, so it must not count as a placeholder.
    [ -f "$1" ] && grep -Eq 'SET_HOSTNAME_HERE|SET_EMAIL_HERE' "$1"
}

copy_config_preserve() {
    src="$1"
    dst="$2"
    install -d -m 0750 "$(dirname "$dst")"
    cp -a "$src" "$dst"
}

link_legacy_config() {
    [ -e "$PREFERRED_CONFIG" ] || return 0
    # /opt/csm holds the binary, ui/, rules/, quarantine/. Don't tighten
    # its mode here - GNU `install -d -m` rewrites the mode on existing
    # dirs, and 0700 would block non-root users from traversing /opt/csm
    # to invoke csm CLI commands.
    [ -d "$(dirname "$LEGACY_CONFIG")" ] || install -d -m 0755 "$(dirname "$LEGACY_CONFIG")"

    if [ -L "$LEGACY_CONFIG" ]; then
        target="$(readlink "$LEGACY_CONFIG" 2>/dev/null || true)"
        [ "$target" = "$PREFERRED_CONFIG" ] && return 0
        rm -f "$LEGACY_CONFIG"
        ln -s "$PREFERRED_CONFIG" "$LEGACY_CONFIG"
        return 0
    fi

    if [ -e "$LEGACY_CONFIG" ]; then
        if [ "$PREFERRED_CONFIG" -ef "$LEGACY_CONFIG" ]; then
            return 0
        fi
        if cmp -s "$PREFERRED_CONFIG" "$LEGACY_CONFIG"; then
            rm -f "$LEGACY_CONFIG"
            ln -s "$PREFERRED_CONFIG" "$LEGACY_CONFIG"
            return 0
        fi
        echo "WARNING: $LEGACY_CONFIG differs from $PREFERRED_CONFIG; leaving both in place." >&2
        return 0
    fi

    ln -s "$PREFERRED_CONFIG" "$LEGACY_CONFIG"
}

migrate_main_config() {
    if [ -e "$LEGACY_CONFIG" ] && [ ! -L "$LEGACY_CONFIG" ]; then
        if [ ! -e "$PREFERRED_CONFIG" ]; then
            copy_config_preserve "$LEGACY_CONFIG" "$PREFERRED_CONFIG"
        elif ! [ "$PREFERRED_CONFIG" -ef "$LEGACY_CONFIG" ] && ! cmp -s "$PREFERRED_CONFIG" "$LEGACY_CONFIG"; then
            if is_placeholder_config "$PREFERRED_CONFIG"; then
                copy_config_preserve "$LEGACY_CONFIG" "$PREFERRED_CONFIG"
            else
                echo "WARNING: $PREFERRED_CONFIG and $LEGACY_CONFIG both exist with different content." >&2
                echo "WARNING: Move one aside or pass --config <path> before starting CSM." >&2
            fi
        fi
    fi

    link_legacy_config
}

migrate_main_config

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
    echo "  Config:       /etc/csm/csm.yaml"
    echo "  Legacy path:  /opt/csm/csm.yaml -> /etc/csm/csm.yaml"
    echo "  Drop-ins:     /etc/csm/conf.d/*.yaml"
    echo "  State:        /var/lib/csm/state/"
    echo "  Profiles:     /usr/lib/csm/profiles/"
    echo "  WebUI:        https://$(hostname -f 2>/dev/null || hostname):9443/"
    echo ""
    echo "Next steps:"
    echo "  1. Review config:   vi /etc/csm/csm.yaml"
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
