#!/bin/bash
# cPanel Security Monitor — Secure deploy from GitLab artifacts
# Downloads the binary + checksum, verifies integrity, installs/upgrades
#
# Usage:
#   deploy.sh install           # First-time install from latest main branch
#   deploy.sh upgrade           # Upgrade existing installation
#   deploy.sh install v1.0.0    # Install specific tag
#   deploy.sh upgrade v1.0.0    # Upgrade to specific tag
#
# Requires GITLAB_TOKEN env var or /opt/csm/.deploy-token file
set -euo pipefail

GITLAB_HOST="git.pidginhost.net"
PROJECT="pidginhost/cpanel-security-monitor"
PROJECT_ENCODED="pidginhost%2Fcpanel-security-monitor"
BINARY_NAME="csm"
INSTALL_DIR="/opt/csm"
BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ARTIFACT_NAME="${BINARY_NAME}-linux-${ARCH}"
JOB_NAME="build:linux-${ARCH}"

# --- Functions ---

die() { echo "ERROR: $1" >&2; exit 1; }

get_token() {
    if [ -n "${GITLAB_TOKEN:-}" ]; then
        echo "$GITLAB_TOKEN"
        return
    fi
    if [ -f "${INSTALL_DIR}/.deploy-token" ]; then
        cat "${INSTALL_DIR}/.deploy-token"
        return
    fi
    die "No GitLab token found. Set GITLAB_TOKEN env var or create ${INSTALL_DIR}/.deploy-token"
}

download_artifact() {
    local ref="$1"
    local token
    token=$(get_token)
    local tmpdir
    tmpdir=$(mktemp -d)

    echo "Downloading ${ARTIFACT_NAME} (ref: ${ref})..."

    # Download binary
    local http_code
    http_code=$(curl -sS -w '%{http_code}' \
        --header "PRIVATE-TOKEN: ${token}" \
        -o "${tmpdir}/${ARTIFACT_NAME}" \
        "https://${GITLAB_HOST}/api/v4/projects/${PROJECT_ENCODED}/jobs/artifacts/${ref}/raw/dist/${ARTIFACT_NAME}?job=${JOB_NAME}")

    if [ "$http_code" != "200" ]; then
        rm -rf "$tmpdir"
        die "Download failed (HTTP ${http_code}). Check ref '${ref}' exists and has a passing pipeline."
    fi

    # Download checksum
    curl -sS \
        --header "PRIVATE-TOKEN: ${token}" \
        -o "${tmpdir}/${ARTIFACT_NAME}.sha256" \
        "https://${GITLAB_HOST}/api/v4/projects/${PROJECT_ENCODED}/jobs/artifacts/${ref}/raw/dist/${ARTIFACT_NAME}.sha256?job=${JOB_NAME}" \
        || die "Failed to download checksum"

    # Verify checksum
    echo "Verifying checksum..."
    cd "$tmpdir"
    if ! sha256sum -c "${ARTIFACT_NAME}.sha256" > /dev/null 2>&1; then
        local expected actual
        expected=$(cat "${ARTIFACT_NAME}.sha256")
        actual=$(sha256sum "${ARTIFACT_NAME}")
        rm -rf "$tmpdir"
        die "Checksum verification FAILED!\n  Expected: ${expected}\n  Got:      ${actual}\n  The binary may have been tampered with."
    fi
    echo "Checksum verified OK"
    cd - > /dev/null

    echo "$tmpdir"
}

do_install() {
    local ref="${1:-main}"

    if [ "$(id -u)" -ne 0 ]; then
        die "Must be run as root"
    fi

    local tmpdir
    tmpdir=$(download_artifact "$ref")

    mkdir -p "$INSTALL_DIR"
    chmod +x "${tmpdir}/${ARTIFACT_NAME}"

    # Verify the binary actually runs
    if ! "${tmpdir}/${ARTIFACT_NAME}" version > /dev/null 2>&1; then
        rm -rf "$tmpdir"
        die "Downloaded binary failed to execute"
    fi

    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"
    rm -rf "$tmpdir"

    echo "Installed: $($BINARY_PATH version)"

    # Run csm install
    "$BINARY_PATH" install

    # Store the deploy token for future upgrades
    if [ -n "${GITLAB_TOKEN:-}" ] && [ ! -f "${INSTALL_DIR}/.deploy-token" ]; then
        echo "$GITLAB_TOKEN" > "${INSTALL_DIR}/.deploy-token"
        chmod 600 "${INSTALL_DIR}/.deploy-token"
        echo "Deploy token saved to ${INSTALL_DIR}/.deploy-token"
    fi

    echo ""
    echo "Install complete. Edit ${INSTALL_DIR}/csm.yaml then run: ${BINARY_PATH} baseline"
}

do_upgrade() {
    local ref="${1:-main}"

    if [ "$(id -u)" -ne 0 ]; then
        die "Must be run as root"
    fi

    if [ ! -f "$BINARY_PATH" ]; then
        die "CSM not installed. Run: $0 install"
    fi

    local old_version
    old_version=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")

    local tmpdir
    tmpdir=$(download_artifact "$ref")

    chmod +x "${tmpdir}/${ARTIFACT_NAME}"

    # Verify the binary runs
    if ! "${tmpdir}/${ARTIFACT_NAME}" version > /dev/null 2>&1; then
        rm -rf "$tmpdir"
        die "Downloaded binary failed to execute"
    fi

    local new_version
    new_version=$("${tmpdir}/${ARTIFACT_NAME}" version)

    # Remove immutable flag, replace binary, re-set immutable
    chattr -i "$BINARY_PATH" 2>/dev/null || true
    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"
    chattr +i "$BINARY_PATH" 2>/dev/null || true
    rm -rf "$tmpdir"

    # Re-baseline with new binary hash
    "$BINARY_PATH" baseline

    echo ""
    echo "Upgrade complete"
    echo "  Old: ${old_version}"
    echo "  New: ${new_version}"
}

# --- Main ---

CMD="${1:-}"
REF="${2:-main}"

case "$CMD" in
    install)
        do_install "$REF"
        ;;
    upgrade)
        do_upgrade "$REF"
        ;;
    *)
        echo "cPanel Security Monitor — Deploy Script"
        echo ""
        echo "Usage:"
        echo "  GITLAB_TOKEN=xxx $0 install [ref]     # First-time install (default ref: main)"
        echo "  GITLAB_TOKEN=xxx $0 upgrade [ref]     # Upgrade existing (default ref: main)"
        echo "  $0 install v1.0.0                     # Install specific tag"
        echo "  $0 upgrade v1.0.0                     # Upgrade to specific tag"
        echo ""
        echo "The GITLAB_TOKEN is saved on first install for future upgrades."
        exit 1
        ;;
esac
