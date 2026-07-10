#!/bin/bash
# Continuous Security Monitor - Standalone Installer
#
# Download and review before running:
#   curl -fsSLo /tmp/csm-install.sh https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh
#   less /tmp/csm-install.sh && sudo bash /tmp/csm-install.sh
#
# Non-interactive:
#   bash install.sh --email admin@example.com --non-interactive
set -euo pipefail

# --- Defaults ---
GITHUB_REPO="pidginhost/csm"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"
INSTALL_DIR="/opt/csm"
BINARY_PATH="${INSTALL_DIR}/csm"
CONFIG_PATH="/etc/csm/csm.yaml"

ARG_EMAIL=""
ARG_HOSTNAME=""
ARG_VERSION=""
ARG_NON_INTERACTIVE=0

# --- Helpers ---
die() { echo "ERROR: $1" >&2; exit 1; }
info() { echo "  $1"; }

# ed25519 public key for verifying release signatures.
#
# Priority (highest first):
#   1. $CSM_SIGNING_KEY_PEM environment variable (operator override)
#   2. Embedded public key below (set at release time)
#
# When neither is present the installer WARNS and proceeds - pre-signing
# releases must still install. To enforce strict signature checking even
# on the install path, set CSM_REQUIRE_SIGNATURES=1.
: "${CSM_SIGNING_KEY_PEM:=}"
: "${CSM_REQUIRE_SIGNATURES:=0}"

# EMBEDDED_SIGNING_KEY is the repo-committed public key used by default.
# Must be a PEM block beginning with -----BEGIN PUBLIC KEY-----. Pairs with
# the ed25519 private key held in the CSM_SIGNING_KEY CI variable.
EMBEDDED_SIGNING_KEY="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEALRRysqHZcownF7dREUhxRaeGP3znMcG0QYH3pou5CPc=
-----END PUBLIC KEY-----"

if [ -z "$CSM_SIGNING_KEY_PEM" ] && [ -n "$EMBEDDED_SIGNING_KEY" ]; then
    CSM_SIGNING_KEY_PEM="$EMBEDDED_SIGNING_KEY"
fi

verify_signature() {
    local file="$1" sig_url="$2"
    if [ -z "$CSM_SIGNING_KEY_PEM" ]; then
        if [ "$CSM_REQUIRE_SIGNATURES" = "1" ]; then
            die "CSM_REQUIRE_SIGNATURES=1 but no signing key configured"
        fi
        echo "  WARNING: no signing key configured, skipping signature verification" >&2
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        if [ "$CSM_REQUIRE_SIGNATURES" = "1" ]; then
            die "CSM_REQUIRE_SIGNATURES=1 but openssl is not installed"
        fi
        echo "  WARNING: openssl not found, skipping signature verification" >&2
        return 0
    fi
    # Ed25519 one-shot verification needs OpenSSL 3.0+ (the -rawin flag). EL8 /
    # CloudLinux 8 ship OpenSSL 1.1.1, which cannot verify Ed25519 from the CLI.
    # Treat that as "cannot verify" (the SHA-256 checksum above is already
    # enforced), never as a tamper -- otherwise upgrades would hard-fail on
    # every 1.1.1 host the moment a release is signed.
    local pkeyutl_help
    pkeyutl_help=$(openssl pkeyutl -help 2>&1 || true)
    if ! grep -q -- '-rawin' <<<"$pkeyutl_help"; then
        if [ "$CSM_REQUIRE_SIGNATURES" = "1" ]; then
            die "CSM_REQUIRE_SIGNATURES=1 but openssl ($(openssl version 2>/dev/null)) lacks Ed25519 one-shot verify (needs OpenSSL 3.0+)"
        fi
        echo "  WARNING: openssl too old for Ed25519 verification (needs 3.0+); skipping signature check (checksum already verified)" >&2
        return 0
    fi
    local sig_file
    sig_file="${file}.sig"
    local sig_http
    sig_http=$(curl -sS -w '%{http_code}' -L -o "$sig_file" "$sig_url")
    if [ "$sig_http" = "404" ] && [ "$CSM_REQUIRE_SIGNATURES" != "1" ]; then
        echo "  WARNING: signature not published for this release (404), skipping verification" >&2
        rm -f "$sig_file"
        return 0
    fi
    if [ "$sig_http" != "200" ]; then
        die "Signature download failed (HTTP ${sig_http}) from ${sig_url}"
    fi
    local key_file
    key_file=$(mktemp)
    printf '%s\n' "$CSM_SIGNING_KEY_PEM" > "$key_file"
    # No RETURN trap for cleanup: it would outlive this function and re-fire
    # at the caller's return, where set -u aborts on the vanished locals.
    local verify_status=0
    openssl pkeyutl -verify -pubin -inkey "$key_file" -rawin -sigfile "$sig_file" -in "$file" >/dev/null 2>&1 || verify_status=$?
    rm -f "$key_file" "$sig_file"
    if [ "$verify_status" -eq 0 ]; then
        info "Signature verified OK"
    else
        die "SIGNATURE VERIFICATION FAILED - binary may be tampered with!"
    fi
}

verify_checksum() {
    local file="$1" checksum_file="$2"
    local expected actual
    expected=$(awk '{print $1}' "$checksum_file")
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
        die "CHECKSUM VERIFICATION FAILED for $(basename "$file")"
    fi
}

validate_assets_archive() {
    local archive="$1" entry type
    while IFS= read -r entry; do
        entry="${entry#./}"
        case "$entry" in
            ""|/*|../*|*/../*|*/..)
                die "Unsafe path in asset archive: ${entry}"
                ;;
        esac
    done < <(tar tzf "$archive")

    while IFS= read -r type; do
        case "$type" in
            -|d) ;;
            *) die "Asset archive contains a link or special file" ;;
        esac
    done < <(tar tvzf "$archive" | awk '{print substr($1,1,1)}')
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
    local arch="$1"
    if [ -n "$ARG_VERSION" ]; then
        local ver="${ARG_VERSION#v}"
        echo "https://github.com/${GITHUB_REPO}/releases/download/${ARG_VERSION}/csm-${ver}-linux-${arch}"
    else
        # Fetch latest tag to build the versioned asset name.
        local tag
        tag=$(curl -sS "${GITHUB_API}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
        [ -z "$tag" ] && die "Could not determine latest release tag"
        local ver="${tag#v}"
        echo "https://github.com/${GITHUB_REPO}/releases/download/${tag}/csm-${ver}-linux-${arch}"
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
ASSETS_URL=$(echo "$BINARY_URL" | sed "s/csm-[^/]*$/csm-assets.tar.gz/")
HTTP_CODE=$(curl -sS -w '%{http_code}' -L -o "${TMPDIR}/assets.tar.gz" "$ASSETS_URL")
[ "$HTTP_CODE" = "200" ] || die "Assets download failed (HTTP ${HTTP_CODE})"
HTTP_CODE=$(curl -sS -w '%{http_code}' -L -o "${TMPDIR}/assets.tar.gz.sha256" "${ASSETS_URL}.sha256")
[ "$HTTP_CODE" = "200" ] || die "Assets checksum download failed (HTTP ${HTTP_CODE})"
verify_checksum "${TMPDIR}/assets.tar.gz" "${TMPDIR}/assets.tar.gz.sha256"
verify_signature "${TMPDIR}/assets.tar.gz" "${ASSETS_URL}.sig"
validate_assets_archive "${TMPDIR}/assets.tar.gz"
tar xzf "${TMPDIR}/assets.tar.gz" -C "$INSTALL_DIR" --no-same-owner --no-same-permissions
for required in ui configs pam deploy.sh; do
    [ -e "${INSTALL_DIR}/${required}" ] || die "Asset archive missing ${required}"
done
mkdir -p "${INSTALL_DIR}/rules"
cp "${INSTALL_DIR}/configs/malware.yml" "${INSTALL_DIR}/rules/"
cp "${INSTALL_DIR}/configs/malware.yar" "${INSTALL_DIR}/rules/"
info "Assets OK"

## Place binary
cp "${TMPDIR}/csm" "$BINARY_PATH"
chmod 0700 "$BINARY_PATH"

# deploy.sh is a required, verified archive member.
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
"$BINARY_PATH" install

# Patch config with detected values
if [ -f "$CONFIG_PATH" ]; then
    sed -i "s/SET_HOSTNAME_HERE/${CONF_HOST}/g" "$CONFIG_PATH" 2>/dev/null || true
    sed -i "s/SET_EMAIL_HERE/${CONF_EMAIL}/g" "$CONFIG_PATH" 2>/dev/null || true
    sed -i "s/auth_token: \"\"/auth_token: \"${AUTH_TOKEN}\"/" "$CONFIG_PATH" 2>/dev/null || true
fi

# Validate
"$BINARY_PATH" validate 2>/dev/null || echo "  WARNING: Config has issues. Run: /opt/csm/csm validate"

echo ""
echo "  ====================================="
echo "   CSM installed successfully!"
echo "  ====================================="
echo ""
echo "  Binary:  /opt/csm/csm"
echo "  Config:  /etc/csm/csm.yaml"
echo "  WebUI:   https://${CONF_HOST}:9443/"
echo "  Token:   ${AUTH_TOKEN}"
echo "  Logs:    /var/log/csm/monitor.log"
echo ""
echo "  Next steps:"
echo "    1. Review config:  vi /etc/csm/csm.yaml"
echo "    2. Start daemon:   systemctl enable --now csm.service"
echo "    3. Set baseline:   /opt/csm/csm baseline"
echo ""
echo "  Upgrade later with:  /opt/csm/deploy.sh upgrade"
echo ""
