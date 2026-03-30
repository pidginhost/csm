#!/bin/bash
# cPanel Security Monitor — Standalone Installer
#
# Quick install:
#   curl -sSL https://get.pidginhost.com/csm | bash -s -- --token YOUR_TOKEN
#
# Non-interactive:
#   bash install.sh --token TOKEN --email admin@example.com --non-interactive
set -euo pipefail

# --- Defaults ---
GITLAB_HOST="git.pidginhost.net"
PROJECT_ENCODED="pidginhost%2Fcpanel-security-monitor"
PKG_BASE="https://${GITLAB_HOST}/api/v4/projects/${PROJECT_ENCODED}/packages/generic/csm"
INSTALL_DIR="/opt/csm"
BINARY_PATH="${INSTALL_DIR}/csm"
CONFIG_PATH="${INSTALL_DIR}/csm.yaml"
TOKEN_FILE="${INSTALL_DIR}/.deploy-token"

ARG_TOKEN=""
ARG_EMAIL=""
ARG_HOSTNAME=""
ARG_NON_INTERACTIVE=0
AUTH_HEADER=""

# --- Helpers ---
die() { echo "ERROR: $1" >&2; exit 1; }
info() { echo "  $1"; }

detect_arch() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        *) die "Unsupported architecture: $(uname -m)" ;;
    esac
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --token)     ARG_TOKEN="$2"; shift 2 ;;
            --email)     ARG_EMAIL="$2"; shift 2 ;;
            --hostname)  ARG_HOSTNAME="$2"; shift 2 ;;
            --non-interactive) ARG_NON_INTERACTIVE=1; shift ;;
            -h|--help)
                echo "Usage: install.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --token TOKEN       GitLab deploy token (or set GITLAB_TOKEN env)"
                echo "  --email EMAIL       Admin alert email"
                echo "  --hostname HOST     Server hostname (auto-detected if omitted)"
                echo "  --non-interactive   Skip all prompts, use defaults"
                exit 0
                ;;
            *) die "Unknown option: $1. Use --help for usage." ;;
        esac
    done
}

prompt() {
    local var_name="$1" prompt_text="$2" default="$3"
    if [ "$ARG_NON_INTERACTIVE" = "1" ]; then
        eval "$var_name=\"$default\""
        return
    fi
    local input=""
    if [ -n "$default" ]; then
        read -rp "  $prompt_text [$default]: " input
        eval "$var_name=\"${input:-$default}\""
    else
        read -rp "  $prompt_text: " input
        eval "$var_name=\"$input\""
    fi
}

get_token() {
    if [ -n "$ARG_TOKEN" ]; then echo "$ARG_TOKEN"; return; fi
    if [ -n "${GITLAB_TOKEN:-}" ]; then echo "$GITLAB_TOKEN"; return; fi
    if [ -f "$TOKEN_FILE" ]; then cat "$TOKEN_FILE"; return; fi

    if [ "$ARG_NON_INTERACTIVE" = "1" ]; then
        die "No token provided. Use --token or set GITLAB_TOKEN env."
    fi

    echo ""
    echo "  A GitLab deploy token is needed to download CSM."
    echo "  Create one at:"
    echo "    https://${GITLAB_HOST}/pidginhost/cpanel-security-monitor/-/settings/repository"
    echo "    -> Deploy tokens -> Scopes: read_package_registry"
    echo ""
    local token=""
    read -rp "  Enter token: " token
    [ -z "$token" ] && die "No token provided."
    echo "$token"
}

detect_auth_header() {
    local token
    token=$(get_token)

    # Try cached type
    if [ -f "${INSTALL_DIR}/.token-type" ]; then
        local cached
        cached=$(cat "${INSTALL_DIR}/.token-type")
        local code
        code=$(curl -sS -w '%{http_code}' -o /dev/null \
            --header "${cached}: ${token}" \
            "${PKG_BASE}/latest/csm-linux-${ARCH}.sha256" 2>/dev/null)
        if [ "$code" = "200" ]; then
            AUTH_HEADER="${cached}: ${token}"
            return
        fi
    fi

    local code
    code=$(curl -sS -w '%{http_code}' -o /dev/null \
        --header "Deploy-Token: ${token}" \
        "${PKG_BASE}/latest/csm-linux-${ARCH}.sha256" 2>/dev/null)
    if [ "$code" = "200" ]; then
        AUTH_HEADER="Deploy-Token: ${token}"
        mkdir -p "$INSTALL_DIR"
        echo "Deploy-Token" > "${INSTALL_DIR}/.token-type" 2>/dev/null || true
        echo "$token" > "$TOKEN_FILE" && chmod 600 "$TOKEN_FILE" 2>/dev/null || true
        return
    fi

    code=$(curl -sS -w '%{http_code}' -o /dev/null \
        --header "PRIVATE-TOKEN: ${token}" \
        "${PKG_BASE}/latest/csm-linux-${ARCH}.sha256" 2>/dev/null)
    if [ "$code" = "200" ]; then
        AUTH_HEADER="PRIVATE-TOKEN: ${token}"
        mkdir -p "$INSTALL_DIR"
        echo "PRIVATE-TOKEN" > "${INSTALL_DIR}/.token-type" 2>/dev/null || true
        echo "$token" > "$TOKEN_FILE" && chmod 600 "$TOKEN_FILE" 2>/dev/null || true
        return
    fi

    die "Token authentication failed (HTTP ${code}). Check token scope: read_package_registry"
}

pkg_download() {
    curl -sS -w '%{http_code}' --header "${AUTH_HEADER}" -o "$2" "$1"
}

# --- Main ---

echo ""
echo "  ====================================="
echo "   CSM - cPanel Security Monitor"
echo "  ====================================="
echo ""

[ "$(id -u)" -ne 0 ] && die "Must be run as root"

parse_args "$@"

# Check existing installation
if [ -f "$BINARY_PATH" ]; then
    CURRENT=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")
    echo "  CSM is already installed: ${CURRENT}"
    echo "  Use /opt/csm/deploy.sh upgrade instead."
    exit 0
fi

ARCH=$(detect_arch)
info "Platform: linux-${ARCH}"

# Authenticate
info "Authenticating..."
detect_auth_header
info "OK"

# Download binary
echo ""
info "Downloading binary..."
mkdir -p "$INSTALL_DIR"
TMPDIR=$(mktemp -d -p "$INSTALL_DIR")
trap "rm -rf '$TMPDIR'" EXIT

HTTP_CODE=$(pkg_download "${PKG_BASE}/latest/csm-linux-${ARCH}" "${TMPDIR}/csm")
[ "$HTTP_CODE" != "200" ] && die "Binary download failed (HTTP ${HTTP_CODE})"

HTTP_CODE=$(pkg_download "${PKG_BASE}/latest/csm-linux-${ARCH}.sha256" "${TMPDIR}/csm.sha256")
[ "$HTTP_CODE" != "200" ] && die "Checksum download failed (HTTP ${HTTP_CODE})"

info "Verifying checksum..."
EXPECTED=$(awk '{print $1}' "${TMPDIR}/csm.sha256")
ACTUAL=$(sha256sum "${TMPDIR}/csm" | awk '{print $1}')
[ "$EXPECTED" != "$ACTUAL" ] && die "CHECKSUM MISMATCH - binary may be tampered!"

chmod +x "${TMPDIR}/csm"
VERSION=$("${TMPDIR}/csm" version 2>/dev/null || die "Binary failed to execute")
info "Version: ${VERSION}"

# Download assets
info "Downloading UI assets and rules..."
HTTP_CODE=$(pkg_download "${PKG_BASE}/latest/csm-assets.tar.gz" "${TMPDIR}/assets.tar.gz")
if [ "$HTTP_CODE" = "200" ]; then
    tar xzf "${TMPDIR}/assets.tar.gz" -C "$INSTALL_DIR" 2>/dev/null || true
    mkdir -p "${INSTALL_DIR}/rules"
    cp "${INSTALL_DIR}/configs/malware.yml" "${INSTALL_DIR}/rules/" 2>/dev/null || true
    cp "${INSTALL_DIR}/configs/malware.yar" "${INSTALL_DIR}/rules/" 2>/dev/null || true
    info "Assets OK"
else
    echo "  WARNING: Assets download failed (HTTP ${HTTP_CODE}), UI may be missing"
fi

# Place binary
cp "${TMPDIR}/csm" "$BINARY_PATH"
chmod 0700 "$BINARY_PATH"

# Also place deploy.sh for future upgrades
cp "${INSTALL_DIR}/configs/deploy.sh" "${INSTALL_DIR}/deploy.sh" 2>/dev/null || true
chmod 755 "${INSTALL_DIR}/deploy.sh" 2>/dev/null || true

# --- Configuration ---
echo ""
echo "  --- Configuration ---"

DETECTED_HOST=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "")
if [ -n "$ARG_HOSTNAME" ]; then
    CONF_HOST="$ARG_HOSTNAME"
else
    prompt CONF_HOST "Hostname" "$DETECTED_HOST"
fi

DETECTED_EMAIL=""
[ -f /var/cpanel/cpanel.config ] && DETECTED_EMAIL=$(grep '^contactemail=' /var/cpanel/cpanel.config 2>/dev/null | cut -d= -f2 || true)
[ -z "$DETECTED_EMAIL" ] && DETECTED_EMAIL="root@${CONF_HOST}"
if [ -n "$ARG_EMAIL" ]; then
    CONF_EMAIL="$ARG_EMAIL"
else
    prompt CONF_EMAIL "Alert email" "$DETECTED_EMAIL"
fi

AUTH_TOKEN=$(head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)

# Run binary install (generates config, systemd, auditd, WHM, logrotate)
info "Installing services..."
"$BINARY_PATH" install 2>/dev/null || true

# Patch config with detected values
if [ -f "$CONFIG_PATH" ]; then
    sed -i "s/SET_HOSTNAME_HERE/${CONF_HOST}/g" "$CONFIG_PATH" 2>/dev/null || true
    sed -i "s/SET_EMAIL_HERE/${CONF_EMAIL}/g" "$CONFIG_PATH" 2>/dev/null || true
    sed -i "s/auth_token: \"\"/auth_token: \"${AUTH_TOKEN}\"/" "$CONFIG_PATH" 2>/dev/null || true
fi

# Immutable
chattr +i "$BINARY_PATH" 2>/dev/null || true

# Validate
"$BINARY_PATH" validate 2>/dev/null || echo "  WARNING: Config has issues. Run: /opt/csm/csm validate"

echo ""
echo "  ====================================="
echo "   CSM installed successfully!"
echo "  ====================================="
echo ""
echo "  Binary:  /opt/csm/csm"
echo "  Config:  /opt/csm/csm.yaml"
echo "  WebUI:   https://${CONF_HOST}:9443/"
echo "  Token:   ${AUTH_TOKEN}"
echo "  Logs:    /var/log/csm/monitor.log"
echo ""
echo "  Next steps:"
echo "    1. Review config:  vi /opt/csm/csm.yaml"
echo "    2. Set baseline:   /opt/csm/csm baseline"
echo "    3. Start daemon:   systemctl enable --now csm.service"
echo ""
echo "  Upgrade later with:  /opt/csm/deploy.sh upgrade"
echo ""
