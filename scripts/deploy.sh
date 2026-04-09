#!/bin/bash
# Continuous Security Monitor — Deploy from GitHub Releases
#
# Downloads the latest binary + SHA256 checksum, verifies integrity,
# and installs or upgrades.
#
# Usage:
#   deploy.sh install        Install latest
#   deploy.sh upgrade        Upgrade to latest
#   deploy.sh check          Check if update available
set -euo pipefail

GITHUB_REPO="pidginhost/csm"
BINARY_NAME="csm"
INSTALL_DIR="/opt/csm"
BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
SERVICE_NAME="csm"
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ARTIFACT_NAME="${BINARY_NAME}-linux-${ARCH}"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"

# --- Functions ---

die() { echo "ERROR: $1" >&2; exit 1; }

# ed25519 public key for verifying release signatures.
# Must be provided via environment or embedded before use.
: "${CSM_SIGNING_KEY_PEM:=}"

verify_signature() {
    local file="$1" sig_url="$2"
    if [ -z "$CSM_SIGNING_KEY_PEM" ]; then
        echo "WARNING: CSM_SIGNING_KEY_PEM not set, skipping signature verification" >&2
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        echo "  WARNING: openssl not found, skipping signature verification" >&2
        return 0
    fi
    local sig_file="${file}.sig"
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
        echo "Signature verified OK" >&2
    else
        die "SIGNATURE VERIFICATION FAILED — binary may be tampered with!"
    fi
}

resolve_release_tag() {
    # Cache the resolved tag for the session.
    if [ -n "${_RESOLVED_TAG:-}" ]; then echo "$_RESOLVED_TAG"; return; fi
    _RESOLVED_TAG=$(curl -sS "${GITHUB_API}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    [ -z "$_RESOLVED_TAG" ] && die "Could not determine latest release tag"
    echo "$_RESOLVED_TAG"
}

get_download_url() {
    local asset="$1" version="${2:-latest}"
    local tag ver
    if [ "$version" = "latest" ]; then
        tag=$(resolve_release_tag)
    else
        tag="$version"
    fi
    ver="${tag#v}"
    # Inject version into binary names: csm-linux-amd64 -> csm-VER-linux-amd64
    asset=$(echo "$asset" | sed "s/^csm-linux-/csm-${ver}-linux-/")
    echo "https://github.com/${GITHUB_REPO}/releases/download/${tag}/${asset}"
}

download_package() {
    local version="${1:-latest}"
    local tmpdir
    mkdir -p "$INSTALL_DIR"
    tmpdir=$(mktemp -d -p "$INSTALL_DIR")

    echo "Downloading ${ARTIFACT_NAME} (version: ${version})..." >&2

    local http_code
    http_code=$(curl -sS -w '%{http_code}' -L -o "${tmpdir}/${ARTIFACT_NAME}" "$(get_download_url "$ARTIFACT_NAME" "$version")")
    if [ "$http_code" != "200" ]; then
        rm -rf "$tmpdir"
        die "Binary download failed (HTTP ${http_code}). Check https://github.com/${GITHUB_REPO}/releases"
    fi

    http_code=$(curl -sS -w '%{http_code}' -L -o "${tmpdir}/${ARTIFACT_NAME}.sha256" "$(get_download_url "${ARTIFACT_NAME}.sha256" "$version")")
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

    verify_signature "${tmpdir}/${ARTIFACT_NAME}" "$(get_download_url "${ARTIFACT_NAME}.sig" "$version")"

    chmod +x "${tmpdir}/${ARTIFACT_NAME}"
    if ! "${tmpdir}/${ARTIFACT_NAME}" version > /dev/null 2>&1; then
        rm -rf "$tmpdir"
        die "Downloaded binary failed to execute."
    fi

    echo "Downloaded: $("${tmpdir}/${ARTIFACT_NAME}" version)" >&2
    echo "$tmpdir"
}

# Stop daemon and timers, wait for clean shutdown
stop_services() {
    echo "Stopping ${SERVICE_NAME}..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl stop csm-critical.timer csm-deep.timer 2>/dev/null || true
    local i=0
    while pgrep -f "${BINARY_PATH} daemon" > /dev/null 2>&1 && [ $i -lt 10 ]; do
        sleep 1
        i=$((i + 1))
    done
    if pgrep -f "${BINARY_PATH} daemon" > /dev/null 2>&1; then
        echo "WARNING: daemon still running after 10s, sending SIGKILL"
        pkill -9 -f "${BINARY_PATH} daemon" 2>/dev/null || true
        sleep 1
    fi
    rm -f "${INSTALL_DIR}/state/csm.lock" "${INSTALL_DIR}/state/csm.pid" 2>/dev/null || true
    systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true
}

start_services() {
    echo "Starting ${SERVICE_NAME}..."
    systemctl start "${SERVICE_NAME}"
    systemctl start csm-critical.timer csm-deep.timer 2>/dev/null || true
    sleep 2
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo "WARNING: ${SERVICE_NAME} failed to start. Check: journalctl -u ${SERVICE_NAME} -n 20"
        return 1
    fi
    echo "Service running (PID $(systemctl show -p MainPID --value "${SERVICE_NAME}"))"
}

do_install() {
    if [ "$(id -u)" -ne 0 ]; then die "Must be run as root"; fi

    echo "=== Continuous Security Monitor — Install ==="
    echo ""

    local tmpdir
    tmpdir=$(download_package "latest")

    mkdir -p "$INSTALL_DIR"
    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"
    rm -rf "$tmpdir"

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

    echo "=== Continuous Security Monitor — Upgrade ==="
    echo ""

    local old_version
    old_version=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")
    echo "Current: ${old_version}"

    stop_services

    local tmpdir
    tmpdir=$(download_package "latest")

    local new_version
    new_version=$("${tmpdir}/${ARTIFACT_NAME}" version)

    if [ "$old_version" = "$new_version" ]; then
        rm -rf "$tmpdir"
        echo "Already running the latest version. Restarting..."
        start_services
        exit 0
    fi

    cp "$BINARY_PATH" "${BINARY_PATH}.bak" 2>/dev/null || true

    chattr -i "$BINARY_PATH" 2>/dev/null || true
    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"

    # Download and extract UI + config assets
    local assets_code
    assets_code=$(curl -sS -w '%{http_code}' -L -o "${tmpdir}/csm-assets.tar.gz" \
        "$(get_download_url "csm-assets.tar.gz" "latest")")
    if [ "$assets_code" = "200" ]; then
        tar xzf "${tmpdir}/csm-assets.tar.gz" -C "$INSTALL_DIR" 2>/dev/null || true
        mkdir -p "${INSTALL_DIR}/rules"
        for f in "${INSTALL_DIR}/configs/malware.yml" "${INSTALL_DIR}/configs/malware.yar"; do
            [ -f "$f" ] && cp "$f" "${INSTALL_DIR}/rules/" || echo "WARNING: rule file not found: $f"
        done
    else
        echo "WARNING: Assets download failed (HTTP ${assets_code}), keeping existing UI/rules"
    fi

    rm -rf "$tmpdir"

    if [ -f "${INSTALL_DIR}/php_shield.php" ]; then
        echo "Updating PHP Shield..."
        "$BINARY_PATH" install --php-shield-only 2>/dev/null || true
    fi

    "$BINARY_PATH" rehash 2>&1 || true
    if ! "$BINARY_PATH" rehash 2>&1; then
        echo "WARNING: Rehash failed, rolling back..."
        cp "${BINARY_PATH}.bak" "$BINARY_PATH" 2>/dev/null || true
        chattr +i "$BINARY_PATH" 2>/dev/null || true
        start_services || true
        die "Upgrade failed — rolled back to previous version"
    fi

    chattr +i "$BINARY_PATH" 2>/dev/null || true
    rm -f "${BINARY_PATH}.bak"

    start_services

    echo ""
    echo "Upgrade complete: ${old_version} -> ${new_version}"
}

do_check() {
    if [ ! -f "$BINARY_PATH" ]; then echo "CSM not installed."; exit 1; fi

    local current
    current=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")
    echo "Installed: ${current}"

    local tmpdir
    mkdir -p "$INSTALL_DIR"
    tmpdir=$(mktemp -d -p "$INSTALL_DIR")

    local http_code
    http_code=$(curl -sS -w '%{http_code}' -L -o "${tmpdir}/latest.sha256" \
        "$(get_download_url "${ARTIFACT_NAME}.sha256" "latest")")

    if [ "$http_code" = "200" ]; then
        local remote_hash local_hash
        remote_hash=$(awk '{print $1}' "${tmpdir}/latest.sha256")
        local_hash=$(sha256sum "$BINARY_PATH" | awk '{print $1}')
        if [ "$remote_hash" = "$local_hash" ]; then
            echo "Up to date."
        else
            echo "Update available. Run: $0 upgrade"
        fi
    else
        echo "Could not fetch latest checksum (HTTP ${http_code})."
    fi

    rm -rf "$tmpdir"
}

# --- Main ---

case "${1:-}" in
    install)  do_install ;;
    upgrade)  do_upgrade ;;
    check)    do_check ;;
    *)
        echo "Continuous Security Monitor — Deploy"
        echo ""
        echo "Usage:"
        echo "  $0 install     Install latest"
        echo "  $0 upgrade     Upgrade to latest"
        echo "  $0 check       Check if update available"
        exit 1
        ;;
esac
