#!/bin/bash
# cPanel Security Monitor — Secure deploy from GitLab Package Registry
#
# Downloads the latest binary + SHA256 checksum, verifies integrity,
# and installs or upgrades.
#
# The server token only needs read_package_registry scope — NO access to
# source code, issues, pipelines, or anything else.
#
# Usage:
#   deploy.sh install        Install latest
#   deploy.sh upgrade        Upgrade to latest
#   deploy.sh check          Check if update available
#
# First run requires: GITLAB_TOKEN env var
# Token is saved at /opt/csm/.deploy-token for future use.
set -euo pipefail

GITLAB_HOST="git.internal.example"
PROJECT_ENCODED="pidginhost%2Fcpanel-security-monitor"
API_BASE="https://${GITLAB_HOST}/api/v4/projects/${PROJECT_ENCODED}"
PKG_BASE="${API_BASE}/packages/generic/csm"
BINARY_NAME="csm"
INSTALL_DIR="/opt/csm"
BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
TOKEN_FILE="${INSTALL_DIR}/.deploy-token"
ARCH=$(uname -m)
AUTH_HEADER=""

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ARTIFACT_NAME="${BINARY_NAME}-linux-${ARCH}"

# --- Functions ---

die() { echo "ERROR: $1" >&2; exit 1; }

get_token() {
    if [ -n "${GITLAB_TOKEN:-}" ]; then
        echo "$GITLAB_TOKEN"
        return
    fi
    if [ -f "$TOKEN_FILE" ]; then
        cat "$TOKEN_FILE"
        return
    fi
    die "No GitLab token found. Set GITLAB_TOKEN env var or create ${TOKEN_FILE}

Create a PROJECT DEPLOY TOKEN at:
  https://${GITLAB_HOST}/pidginhost/cpanel-security-monitor/-/settings/repository
  -> Deploy tokens
  -> Name: csm-deploy-\$(hostname)
  -> Scopes: read_package_registry ONLY"
}

# Detect whether this is a personal token or deploy token
detect_auth_header() {
    local token
    token=$(get_token)

    # Try Deploy-Token first (project deploy tokens)
    local code
    code=$(curl -sS -w '%{http_code}' -o /dev/null \
        --header "Deploy-Token: ${token}" \
        "${PKG_BASE}/latest/${ARTIFACT_NAME}.sha256" 2>/dev/null)

    if [ "$code" = "200" ]; then
        AUTH_HEADER="Deploy-Token: ${token}"
        return
    fi

    # Try PRIVATE-TOKEN (personal access tokens)
    code=$(curl -sS -w '%{http_code}' -o /dev/null \
        --header "PRIVATE-TOKEN: ${token}" \
        "${PKG_BASE}/latest/${ARTIFACT_NAME}.sha256" 2>/dev/null)

    if [ "$code" = "200" ]; then
        AUTH_HEADER="PRIVATE-TOKEN: ${token}"
        return
    fi

    die "Token authentication failed (HTTP ${code}). Check token has read_package_registry scope."
}

save_token() {
    if [ -n "${GITLAB_TOKEN:-}" ]; then
        mkdir -p "$INSTALL_DIR"
        echo "$GITLAB_TOKEN" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        chown root:root "$TOKEN_FILE"
    fi
}

# Download a file from package registry using detected auth
pkg_download() {
    local url="$1"
    local output="$2"
    curl -sS -w '%{http_code}' --header "${AUTH_HEADER}" -o "$output" "$url"
}

download_package() {
    local version="${1:-latest}"
    local tmpdir
    mkdir -p "$INSTALL_DIR"
    tmpdir=$(mktemp -d -p "$INSTALL_DIR")

    echo "Downloading ${ARTIFACT_NAME} (version: ${version})..." >&2

    local http_code
    http_code=$(pkg_download "${PKG_BASE}/${version}/${ARTIFACT_NAME}" "${tmpdir}/${ARTIFACT_NAME}")
    if [ "$http_code" != "200" ]; then
        rm -rf "$tmpdir"
        die "Binary download failed (HTTP ${http_code})."
    fi

    http_code=$(pkg_download "${PKG_BASE}/${version}/${ARTIFACT_NAME}.sha256" "${tmpdir}/${ARTIFACT_NAME}.sha256")
    if [ "$http_code" != "200" ]; then
        rm -rf "$tmpdir"
        die "Checksum download failed (HTTP ${http_code})."
    fi

    # Verify checksum
    echo "Verifying SHA256 checksum..." >&2
    local expected_hash actual_hash
    expected_hash=$(awk '{print $1}' "${tmpdir}/${ARTIFACT_NAME}.sha256")
    actual_hash=$(sha256sum "${tmpdir}/${ARTIFACT_NAME}" | awk '{print $1}')
    if [ "$expected_hash" != "$actual_hash" ]; then
        rm -rf "$tmpdir"
        die "CHECKSUM VERIFICATION FAILED!
  Expected: ${expected_hash}
  Got:      ${actual_hash}
  The binary may have been tampered with."
    fi
    echo "Checksum OK (${actual_hash:0:16}...)" >&2

    chmod +x "${tmpdir}/${ARTIFACT_NAME}"
    if ! "${tmpdir}/${ARTIFACT_NAME}" version > /dev/null 2>&1; then
        rm -rf "$tmpdir"
        die "Downloaded binary failed to execute."
    fi

    echo "Downloaded: $("${tmpdir}/${ARTIFACT_NAME}" version)" >&2
    # Only output the tmpdir path to stdout (for capture)
    echo "$tmpdir"
}

do_install() {
    if [ "$(id -u)" -ne 0 ]; then die "Must be run as root"; fi

    echo "=== cPanel Security Monitor — Install ==="
    echo ""
    detect_auth_header

    local tmpdir
    tmpdir=$(download_package "latest")

    mkdir -p "$INSTALL_DIR"
    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"
    rm -rf "$tmpdir"

    save_token
    "$BINARY_PATH" install

    echo ""
    echo "=== Next steps ==="
    echo "  1. Edit config:    vi ${INSTALL_DIR}/csm.yaml"
    echo "  2. Set baseline:   ${BINARY_PATH} baseline (or 'rehash' for hash-only update)"
    echo "  3. Test:           ${BINARY_PATH} check"
}

do_upgrade() {
    if [ "$(id -u)" -ne 0 ]; then die "Must be run as root"; fi
    if [ ! -f "$BINARY_PATH" ]; then die "CSM not installed. Run: $0 install"; fi

    echo "=== cPanel Security Monitor — Upgrade ==="
    echo ""
    detect_auth_header

    local old_version
    old_version=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")
    echo "Current: ${old_version}"

    local tmpdir
    tmpdir=$(download_package "latest")

    local new_version
    new_version=$("${tmpdir}/${ARTIFACT_NAME}" version)

    if [ "$old_version" = "$new_version" ]; then
        rm -rf "$tmpdir"
        echo "Already running the latest version."
        exit 0
    fi

    save_token

    # Stop timers
    systemctl stop csm-critical.timer csm-deep.timer 2>/dev/null || true

    # Backup
    cp "$BINARY_PATH" "${BINARY_PATH}.bak" 2>/dev/null || true
    cp "${INSTALL_DIR}/csm.yaml" "${INSTALL_DIR}/csm.yaml.bak" 2>/dev/null || true

    # Swap binary
    chattr -i "$BINARY_PATH" 2>/dev/null || true
    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"

    # Download and extract UI + config assets
    local assets_code
    assets_code=$(pkg_download "${PKG_BASE}/latest/csm-assets.tar.gz" "${tmpdir}/csm-assets.tar.gz")
    if [ "$assets_code" = "200" ]; then
        tar xzf "${tmpdir}/csm-assets.tar.gz" -C "$INSTALL_DIR" 2>/dev/null || true
        # Copy signature rules from configs/ to the active rules/ directory
        cp "${INSTALL_DIR}/configs/malware.yml" "${INSTALL_DIR}/rules/malware.yml" 2>/dev/null || true
        cp "${INSTALL_DIR}/configs/malware.yar" "${INSTALL_DIR}/rules/malware.yar" 2>/dev/null || true
    fi

    rm -rf "$tmpdir"

    # Rehash — update binary/config hashes without full re-scan
    if ! "$BINARY_PATH" rehash 2>&1; then
        echo "WARNING: Rehash failed, rolling back..."
        cp "${BINARY_PATH}.bak" "$BINARY_PATH" 2>/dev/null || true
        cp "${INSTALL_DIR}/csm.yaml.bak" "${INSTALL_DIR}/csm.yaml" 2>/dev/null || true
        chattr +i "$BINARY_PATH" 2>/dev/null || true
        systemctl start csm-critical.timer csm-deep.timer 2>/dev/null || true
        die "Upgrade failed — rolled back"
    fi

    chattr +i "$BINARY_PATH" 2>/dev/null || true
    systemctl start csm-critical.timer csm-deep.timer 2>/dev/null || true

    echo ""
    echo "Upgrade complete: ${old_version} -> ${new_version}"
}

do_check() {
    if [ ! -f "$BINARY_PATH" ]; then echo "CSM not installed."; exit 1; fi
    detect_auth_header

    local current
    current=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")
    echo "Installed: ${current}"

    local tmpdir
    mkdir -p "$INSTALL_DIR"
    tmpdir=$(mktemp -d -p "$INSTALL_DIR")

    local http_code
    http_code=$(pkg_download "${PKG_BASE}/latest/${ARTIFACT_NAME}" "${tmpdir}/${ARTIFACT_NAME}")

    if [ "$http_code" = "200" ]; then
        chmod +x "${tmpdir}/${ARTIFACT_NAME}"
        local latest
        latest=$("${tmpdir}/${ARTIFACT_NAME}" version 2>/dev/null || echo "unknown")
        echo "Latest:    ${latest}"
        if [ "$current" = "$latest" ]; then
            echo "Up to date."
        else
            echo "Update available. Run: $0 upgrade"
        fi
    else
        echo "Could not fetch latest (HTTP ${http_code})."
    fi

    rm -rf "$tmpdir"
}

# --- Main ---

case "${1:-}" in
    install)  do_install ;;
    upgrade)  do_upgrade ;;
    check)    do_check ;;
    *)
        echo "cPanel Security Monitor — Deploy"
        echo ""
        echo "Usage:"
        echo "  $0 install     Install latest"
        echo "  $0 upgrade     Upgrade to latest"
        echo "  $0 check       Check if update available"
        echo ""
        echo "Requires GITLAB_TOKEN env var on first run (saved for future use)."
        echo "Token scope: read_package_registry ONLY"
        exit 1
        ;;
esac
