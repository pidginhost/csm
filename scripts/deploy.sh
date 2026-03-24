#!/bin/bash
# cPanel Security Monitor — Secure deploy from GitLab CI artifacts
#
# Downloads the latest binary + SHA256 checksum from the GitLab CI pipeline,
# verifies integrity, and installs or upgrades.
#
# Usage:
#   deploy.sh install               # First-time install (latest from main)
#   deploy.sh upgrade               # Upgrade to latest from main
#   deploy.sh install v1.0.0        # Install specific tag
#   deploy.sh upgrade v1.0.0        # Upgrade to specific tag
#   deploy.sh check                 # Check if upgrade available
#
# First run requires: GITLAB_TOKEN env var
# Token is saved at /opt/csm/.deploy-token for future use.
set -euo pipefail

GITLAB_HOST="git.pidginhost.net"
PROJECT_ENCODED="pidginhost%2Fcpanel-security-monitor"
API_BASE="https://${GITLAB_HOST}/api/v4/projects/${PROJECT_ENCODED}"
BINARY_NAME="csm"
INSTALL_DIR="/opt/csm"
BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
TOKEN_FILE="${INSTALL_DIR}/.deploy-token"
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
    if [ -f "$TOKEN_FILE" ]; then
        cat "$TOKEN_FILE"
        return
    fi
    die "No GitLab token found. Set GITLAB_TOKEN env var or create ${TOKEN_FILE}

Create a token at: https://${GITLAB_HOST}/-/user_settings/personal_access_tokens
  - Name: csm-deploy
  - Scopes: read_api
  - Expiration: optional (set a reminder if you set one)"
}

save_token() {
    if [ -n "${GITLAB_TOKEN:-}" ]; then
        mkdir -p "$INSTALL_DIR"
        echo "$GITLAB_TOKEN" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        chown root:root "$TOKEN_FILE"
    fi
}

resolve_ref() {
    local requested="${1:-latest}"
    local token
    token=$(get_token)

    if [ "$requested" != "latest" ]; then
        echo "$requested"
        return
    fi

    # Find the latest successful pipeline on main and get its SHA
    local response
    response=$(curl -sS \
        --header "PRIVATE-TOKEN: ${token}" \
        "${API_BASE}/pipelines?ref=main&status=success&per_page=1" 2>/dev/null)

    local sha
    sha=$(echo "$response" | grep -o '"sha":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$sha" ]; then
        # Fallback to branch name
        echo "main"
        return
    fi

    echo "$sha"
}

get_latest_version() {
    local token
    token=$(get_token)

    # Get the latest tag
    local response
    response=$(curl -sS \
        --header "PRIVATE-TOKEN: ${token}" \
        "${API_BASE}/repository/tags?per_page=1&order_by=version" 2>/dev/null)

    echo "$response" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4
}

download_artifact() {
    local ref="$1"
    local token
    token=$(get_token)
    local tmpdir
    mkdir -p "$INSTALL_DIR"
    tmpdir=$(mktemp -d -p "$INSTALL_DIR")

    echo "Downloading ${ARTIFACT_NAME} (ref: ${ref:0:12})..."

    # Download binary
    local http_code
    http_code=$(curl -sS -w '%{http_code}' \
        --header "PRIVATE-TOKEN: ${token}" \
        -o "${tmpdir}/${ARTIFACT_NAME}" \
        "${API_BASE}/jobs/artifacts/${ref}/raw/dist/${ARTIFACT_NAME}?job=${JOB_NAME}")

    if [ "$http_code" != "200" ]; then
        rm -rf "$tmpdir"
        die "Download failed (HTTP ${http_code}). Check that ref '${ref}' exists and has a passing pipeline."
    fi

    # Download checksum
    http_code=$(curl -sS -w '%{http_code}' \
        --header "PRIVATE-TOKEN: ${token}" \
        -o "${tmpdir}/${ARTIFACT_NAME}.sha256" \
        "${API_BASE}/jobs/artifacts/${ref}/raw/dist/${ARTIFACT_NAME}.sha256?job=${JOB_NAME}")

    if [ "$http_code" != "200" ]; then
        rm -rf "$tmpdir"
        die "Checksum download failed (HTTP ${http_code})."
    fi

    # Verify checksum
    echo "Verifying SHA256 checksum..."
    local expected_hash actual_hash
    expected_hash=$(awk '{print $1}' "${tmpdir}/${ARTIFACT_NAME}.sha256")
    actual_hash=$(sha256sum "${tmpdir}/${ARTIFACT_NAME}" | awk '{print $1}')
    if [ "$expected_hash" != "$actual_hash" ]; then
        rm -rf "$tmpdir"
        die "CHECKSUM VERIFICATION FAILED!
  Expected: ${expected_hash}
  Got:      ${actual_hash}
  The binary may have been tampered with. Do not use it."
    fi
    echo "Checksum OK (${actual_hash:0:16}...)"

    # Verify binary executes
    chmod +x "${tmpdir}/${ARTIFACT_NAME}"
    if ! "${tmpdir}/${ARTIFACT_NAME}" version > /dev/null 2>&1; then
        rm -rf "$tmpdir"
        die "Downloaded binary failed to execute."
    fi

    local version
    version=$("${tmpdir}/${ARTIFACT_NAME}" version)
    echo "Downloaded: ${version}"

    echo "$tmpdir"
}

do_install() {
    local ref
    ref=$(resolve_ref "${1:-latest}")

    if [ "$(id -u)" -ne 0 ]; then
        die "Must be run as root"
    fi

    echo "=== cPanel Security Monitor — Install ==="
    echo ""

    local tmpdir
    tmpdir=$(download_artifact "$ref")

    mkdir -p "$INSTALL_DIR"
    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"
    rm -rf "$tmpdir"

    # Save token for future upgrades
    save_token

    # Run csm install (sets up systemd, auditd, config)
    "$BINARY_PATH" install

    echo ""
    echo "=== Next steps ==="
    echo "  1. Edit config:    vi ${INSTALL_DIR}/csm.yaml"
    echo "  2. Set baseline:   ${BINARY_PATH} baseline"
    echo "  3. Test:           ${BINARY_PATH} check"
}

do_upgrade() {
    local ref
    ref=$(resolve_ref "${1:-latest}")

    if [ "$(id -u)" -ne 0 ]; then
        die "Must be run as root"
    fi

    if [ ! -f "$BINARY_PATH" ]; then
        die "CSM not installed. Run: $0 install"
    fi

    echo "=== cPanel Security Monitor — Upgrade ==="
    echo ""

    local old_version
    old_version=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")
    echo "Current: ${old_version}"

    local tmpdir
    tmpdir=$(download_artifact "$ref")

    local new_version
    new_version=$("${tmpdir}/${ARTIFACT_NAME}" version)

    if [ "$old_version" = "$new_version" ]; then
        rm -rf "$tmpdir"
        echo ""
        echo "Already running the latest version. Nothing to do."
        exit 0
    fi

    # Save token if provided
    save_token

    # Stop timers during upgrade
    systemctl stop csm-critical.timer csm-deep.timer 2>/dev/null || true

    # Backup current binary and config
    cp "$BINARY_PATH" "${BINARY_PATH}.bak" 2>/dev/null || true
    cp "${INSTALL_DIR}/csm.yaml" "${INSTALL_DIR}/csm.yaml.bak" 2>/dev/null || true
    echo "Backup created: ${BINARY_PATH}.bak"

    # Swap binary: remove immutable, copy, re-set immutable
    chattr -i "$BINARY_PATH" 2>/dev/null || true
    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"
    rm -rf "$tmpdir"

    # Re-baseline with new binary hash
    if ! "$BINARY_PATH" baseline 2>&1; then
        echo "WARNING: Baseline failed, rolling back..."
        cp "${BINARY_PATH}.bak" "$BINARY_PATH" 2>/dev/null || true
        cp "${INSTALL_DIR}/csm.yaml.bak" "${INSTALL_DIR}/csm.yaml" 2>/dev/null || true
        chattr +i "$BINARY_PATH" 2>/dev/null || true
        systemctl start csm-critical.timer csm-deep.timer 2>/dev/null || true
        die "Upgrade failed — rolled back to previous version"
    fi

    chattr +i "$BINARY_PATH" 2>/dev/null || true

    # Restart timers
    systemctl start csm-critical.timer csm-deep.timer 2>/dev/null || true

    echo ""
    echo "Upgrade complete"
    echo "  Old: ${old_version}"
    echo "  New: ${new_version}"
}

do_check() {
    if [ ! -f "$BINARY_PATH" ]; then
        echo "CSM not installed."
        exit 1
    fi

    local current
    current=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")
    echo "Installed: ${current}"

    local ref
    ref=$(resolve_ref "latest")
    local token
    token=$(get_token)

    # Download just the version from latest artifact (small check)
    local tmpdir
    mkdir -p "$INSTALL_DIR"
    tmpdir=$(mktemp -d -p "$INSTALL_DIR")
    local http_code
    http_code=$(curl -sS -w '%{http_code}' \
        --header "PRIVATE-TOKEN: ${token}" \
        -o "${tmpdir}/${ARTIFACT_NAME}" \
        "${API_BASE}/jobs/artifacts/${ref}/raw/dist/${ARTIFACT_NAME}?job=${JOB_NAME}" 2>/dev/null)

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
        echo "Could not fetch latest version (HTTP ${http_code})."
    fi

    rm -rf "$tmpdir"
}

# --- Main ---

CMD="${1:-}"
REF="${2:-}"

case "$CMD" in
    install)
        do_install "$REF"
        ;;
    upgrade)
        do_upgrade "$REF"
        ;;
    check)
        do_check
        ;;
    *)
        echo "cPanel Security Monitor — Deploy"
        echo ""
        echo "Usage:"
        echo "  $0 install              Install latest from main branch"
        echo "  $0 install v1.0.0       Install specific tag"
        echo "  $0 upgrade              Upgrade to latest from main"
        echo "  $0 upgrade v1.0.0       Upgrade to specific tag"
        echo "  $0 check                Check if update available"
        echo ""
        echo "First run requires GITLAB_TOKEN env var (saved for future use)."
        echo ""
        echo "Create token at: https://${GITLAB_HOST}/-/user_settings/personal_access_tokens"
        echo "  Scope: read_api | Name: csm-deploy"
        exit 1
        ;;
esac
