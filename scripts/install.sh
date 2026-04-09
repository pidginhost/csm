#!/bin/bash
# Continuous Security Monitor — Standalone Installer
#
# Quick install:
#   curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
#
# Non-interactive:
#   bash install.sh --email admin@example.com --non-interactive
set -euo pipefail

# --- Defaults ---
GITHUB_REPO="pidginhost/csm"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
INSTALL_DIR="/opt/csm"
BINARY_PATH="${INSTALL_DIR}/csm"
CONFIG_PATH="${INSTALL_DIR}/csm.yaml"

ARG_EMAIL=""
ARG_HOSTNAME=""
ARG_VERSION=""
ARG_NON_INTERACTIVE=0

# --- Helpers ---
die() { echo "ERROR: $1" >&2; exit 1; }
info() { echo "  $1"; }

# ed25519 public key for verifying release signatures.
# Must be provided via environment or embedded before use.
: "${CSM_SIGNING_KEY_PEM:=}"

verify_signature() {
    local file="$1" sig_url="$2"
    if [ -z "$CSM_SIGNING_KEY_PEM" ]; then
        die "CSM_SIGNING_KEY_PEM is not set; refusing unsigned install"
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        echo "  WARNING: openssl not found, skipping signature verification" >&2
        return 0
    fi
    local sig_file
    sig_file="${file}.sig"
    local sig_http
    sig_http=$(curl -sS -w '%{http_code}' -L -o "$sig_file" "$sig_url")
    if [ "$sig_http" != "200" ]; then
        die "Signature download failed (HTTP ${sig_http}) from ${sig_url}"
    fi
    local key_file
    key_file=$(mktemp)
    trap 'rm -f "$key_file" "$sig_file"' RETURN
    printf '%s\n' "$CSM_SIGNING_KEY_PEM" > "$key_file"
    if openssl pkeyutl -verify -pubin -inkey "$key_file" -rawin -sigfile "$sig_file" -in "$file" >/dev/null 2>&1; then
        info "Signature verified OK"
    else
        die "SIGNATURE VERIFICATION FAILED — binary may be tampered with!"
    fi
}

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
            --email)     ARG_EMAIL="$2"; shift 2 ;;
            --hostname)  ARG_HOSTNAME="$2"; shift 2 ;;
            --version)   ARG_VERSION="$2"; shift 2 ;;
            --non-interactive) ARG_NON_INTERACTIVE=1; shift ;;
            -h|--help)
                echo "Usage: install.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --email EMAIL       Admin alert email"
                echo "  --hostname HOST     Server hostname (auto-detected if omitted)"
                echo "  --version TAG       Install specific version (default: latest)"
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

get_download_url() {
    local arch="$1" asset="csm-linux-${arch}"
    if [ -n "$ARG_VERSION" ]; then
        echo "https://github.com/${GITHUB_REPO}/releases/download/${ARG_VERSION}/${asset}"
    else
        echo "https://github.com/${GITHUB_REPO}/releases/latest/download/${asset}"
    fi
}

# --- Main ---

echo ""
echo "  ====================================="
echo "   CSM - Continuous Security Monitor"
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

# Download binary
echo ""
info "Downloading binary..."
mkdir -p "$INSTALL_DIR"
TMPDIR=$(mktemp -d -p "$INSTALL_DIR")
trap "rm -rf '$TMPDIR'" EXIT

BINARY_URL=$(get_download_url "$ARCH")
CHECKSUM_URL="${BINARY_URL}.sha256"

HTTP_CODE=$(curl -sS -w '%{http_code}' -L -o "${TMPDIR}/csm" "$BINARY_URL")
[ "$HTTP_CODE" != "200" ] && die "Binary download failed (HTTP ${HTTP_CODE}). Check https://github.com/${GITHUB_REPO}/releases"

HTTP_CODE=$(curl -sS -w '%{http_code}' -L -o "${TMPDIR}/csm.sha256" "$CHECKSUM_URL")
[ "$HTTP_CODE" != "200" ] && die "Checksum download failed (HTTP ${HTTP_CODE})"

info "Verifying checksum..."
EXPECTED=$(awk '{print $1}' "${TMPDIR}/csm.sha256")
ACTUAL=$(sha256sum "${TMPDIR}/csm" | awk '{print $1}')
[ "$EXPECTED" != "$ACTUAL" ] && die "CHECKSUM MISMATCH - binary may be tampered!"

verify_signature "${TMPDIR}/csm" "${BINARY_URL}.sig"

chmod +x "${TMPDIR}/csm"
VERSION=$("${TMPDIR}/csm" version 2>/dev/null || die "Binary failed to execute")
info "Version: ${VERSION}"

# Download assets
info "Downloading UI assets and rules..."
ASSETS_URL=$(get_download_url "$ARCH" | sed "s/csm-linux-${ARCH}/csm-assets.tar.gz/")
HTTP_CODE=$(curl -sS -w '%{http_code}' -L -o "${TMPDIR}/assets.tar.gz" "$ASSETS_URL")
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
