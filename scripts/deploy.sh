#!/bin/bash
# Continuous Security Monitor - Deploy from GitHub Releases
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
#
# Priority:
#   1. $CSM_SIGNING_KEY_PEM environment variable
#   2. Embedded public key below
# Set CSM_REQUIRE_SIGNATURES=1 to fail rather than warn on missing key/sig.
: "${CSM_SIGNING_KEY_PEM:=}"
: "${CSM_REQUIRE_SIGNATURES:=0}"

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
        echo "WARNING: no signing key configured, skipping signature verification" >&2
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
    local sig_file="${file}.sig"
    local sig_http
    sig_http=$(curl -sS -w '%{http_code}' -L -o "$sig_file" "$sig_url")
    if [ "$sig_http" = "404" ] && [ "$CSM_REQUIRE_SIGNATURES" != "1" ]; then
        echo "WARNING: signature not published for this release (404), skipping verification" >&2
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
        echo "Signature verified OK" >&2
    else
        die "SIGNATURE VERIFICATION FAILED - artifact may be tampered with!"
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

verify_checksum() {
    local file="$1" checksum_file="$2"
    local expected actual
    expected=$(awk '{print $1}' "$checksum_file")
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
        die "CHECKSUM VERIFICATION FAILED for $(basename "$file")"
    fi
}

missing_assets_checksum_allowed() {
    local version="${1#v}"
    local major minor patch
    if [[ ! "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        return 1
    fi
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    patch="${BASH_REMATCH[3]}"

    # v3.23.1 was the last release published without an assets checksum.
    if [ "$major" -lt 3 ]; then
        return 0
    fi
    if [ "$major" -gt 3 ] || [ "$minor" -gt 23 ]; then
        return 1
    fi
    if [ "$minor" -lt 23 ]; then
        return 0
    fi
    [ "$patch" -le 1 ]
}

validate_assets_archive() {
    local archive="$1" entry type
    local listing="${archive}.entries"
    # Listings are written to a file first so tar's exit status is checked;
    # a process substitution would silently validate a truncated listing.
    if ! tar tzf "$archive" > "$listing" 2>/dev/null; then
        die "Asset archive is corrupt or unreadable"
    fi
    while IFS= read -r entry; do
        entry="${entry#./}"
        case "$entry" in
            ""|.|..|/*|../*|*/../*|*/..)
                die "Unsafe path in asset archive: ${entry}"
                ;;
        esac
    done < "$listing"

    if ! tar tvzf "$archive" > "$listing" 2>/dev/null; then
        die "Asset archive is corrupt or unreadable"
    fi
    while IFS= read -r type; do
        case "$type" in
            -|d) ;;
            *) die "Asset archive contains a link or special file" ;;
        esac
    done < <(awk '{print substr($1,1,1)}' "$listing")
    rm -f "$listing"
}

download_and_stage_assets() {
    local version="$1" tmpdir="$2"
    local archive="${tmpdir}/csm-assets.tar.gz"
    local checksum="${archive}.sha256"
    local code release_version

    release_version=$("${tmpdir}/${ARTIFACT_NAME}" version | awk '{print $2}')

    code=$(curl -sS -w '%{http_code}' -L -o "$archive" \
        "$(get_download_url "csm-assets.tar.gz" "$version")")
    [ "$code" = "200" ] || die "Assets download failed (HTTP ${code})"
    code=$(curl -sS -w '%{http_code}' -L -o "$checksum" \
        "$(get_download_url "csm-assets.tar.gz.sha256" "$version")")
    if [ "$code" = "200" ]; then
        verify_checksum "$archive" "$checksum"
    elif [ "$code" = "404" ] && [ "$CSM_REQUIRE_SIGNATURES" != "1" ] && missing_assets_checksum_allowed "$release_version"; then
        echo "WARNING: assets checksum not published for this release (404), skipping checksum verification" >&2
        rm -f "$checksum"
    else
        die "Assets checksum download failed (HTTP ${code})"
    fi
    verify_signature "$archive" "$(get_download_url "csm-assets.tar.gz.sig" "$version")"
    validate_assets_archive "$archive"

    local stage="${tmpdir}/assets-stage"
    mkdir -p "$stage"
    tar xzf "$archive" -C "$stage" --no-same-owner --no-same-permissions || die "Asset archive extraction failed"
    for required in ui configs pam deploy.sh; do
        [ -e "${stage}/${required}" ] || die "Asset archive missing ${required}"
    done
    echo "$stage"
}

activate_assets() {
    local stage="$1" backup="$2" entry file
    mkdir -p "$backup" "${backup}/rules"
    for entry in ui configs pam deploy.sh; do
        if [ -e "${INSTALL_DIR}/${entry}" ] || [ -L "${INSTALL_DIR}/${entry}" ]; then
            mv "${INSTALL_DIR}/${entry}" "${backup}/${entry}" || return 1
        fi
        mv "${stage}/${entry}" "${INSTALL_DIR}/${entry}" || return 1
    done

    mkdir -p "${INSTALL_DIR}/rules"
    for file in malware.yml malware.yar; do
        if [ -f "${INSTALL_DIR}/rules/${file}" ]; then
            cp -p "${INSTALL_DIR}/rules/${file}" "${backup}/rules/${file}" || return 1
        fi
        cp "${INSTALL_DIR}/configs/${file}" "${INSTALL_DIR}/rules/${file}" || return 1
    done
}

rollback_assets() {
    local backup="$1" entry file
    for entry in ui configs pam deploy.sh; do
        rm -rf "${INSTALL_DIR:?}/${entry}"
        if [ -e "${backup}/${entry}" ] || [ -L "${backup}/${entry}" ]; then
            mv "${backup}/${entry}" "${INSTALL_DIR}/${entry}"
        fi
    done
    for file in malware.yml malware.yar; do
        rm -f "${INSTALL_DIR}/rules/${file}"
        if [ -f "${backup}/rules/${file}" ]; then
            cp -p "${backup}/rules/${file}" "${INSTALL_DIR}/rules/${file}"
        fi
    done
}

cleanup_upgrade_backup() {
    rm -rf "$1"
}

# Stop daemon, wait for clean shutdown
stop_services() {
    echo "Stopping ${SERVICE_NAME}..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
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
    systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true
}

start_services() {
    echo "Starting ${SERVICE_NAME}..."
    systemctl start "${SERVICE_NAME}"
    sleep 2
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo "WARNING: ${SERVICE_NAME} failed to start. Check: journalctl -u ${SERVICE_NAME} -n 20"
        return 1
    fi
    echo "Service running (PID $(systemctl show -p MainPID --value "${SERVICE_NAME}"))"
}

do_install() {
    if [ "$(id -u)" -ne 0 ]; then die "Must be run as root"; fi

    if [ -e "$BINARY_PATH" ]; then die "CSM is already installed. Run: $0 upgrade"; fi

    echo "=== Continuous Security Monitor - Install ==="
    echo ""

    local tmpdir
    tmpdir=$(download_package "latest")

    local assets_stage asset_backup
    assets_stage=$(download_and_stage_assets "latest" "$tmpdir")
    asset_backup="${tmpdir}/asset-backup"

    mkdir -p "$INSTALL_DIR"
    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"
    chmod 0700 "$BINARY_PATH"
    if ! activate_assets "$assets_stage" "$asset_backup"; then
        rollback_assets "$asset_backup"
        rm -f "$BINARY_PATH"
        die "Asset installation failed"
    fi

    if ! "$BINARY_PATH" install; then
        rollback_assets "$asset_backup"
        rm -f "$BINARY_PATH"
        die "Installation failed"
    fi
    cleanup_upgrade_backup "$tmpdir"

    echo ""
    echo "=== Next steps ==="
    echo "  1. Edit config:    vi /etc/csm/csm.yaml"
    echo "  2. Start daemon:   systemctl enable --now csm.service"
    echo "  3. Set baseline:   ${BINARY_PATH} baseline"
    echo "  4. Test:           ${BINARY_PATH} check"
}

do_upgrade() {
    if [ "$(id -u)" -ne 0 ]; then die "Must be run as root"; fi
    if [ ! -f "$BINARY_PATH" ]; then die "CSM not installed. Run: $0 install"; fi

    echo "=== Continuous Security Monitor - Upgrade ==="
    echo ""

    local old_version
    old_version=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")
    echo "Current: ${old_version}"

    local tmpdir
    tmpdir=$(download_package "latest")

    local assets_stage asset_backup binary_backup
    assets_stage=$(download_and_stage_assets "latest" "$tmpdir")
    asset_backup="${tmpdir}/asset-backup"
    binary_backup="${tmpdir}/${ARTIFACT_NAME}.previous"

    local new_version
    new_version=$("${tmpdir}/${ARTIFACT_NAME}" version)

    if [ "$old_version" = "$new_version" ]; then
        rm -rf "$tmpdir"
        echo "Already running the latest version."
        return
    fi

    stop_services
    cp -p "$BINARY_PATH" "$binary_backup"

    chattr -i "$BINARY_PATH" 2>/dev/null || true
    cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"
    chmod 0700 "$BINARY_PATH"
    if ! activate_assets "$assets_stage" "$asset_backup"; then
        chattr -i "$BINARY_PATH" 2>/dev/null || true
        cp -p "$binary_backup" "$BINARY_PATH"
        rollback_assets "$asset_backup"
        "$BINARY_PATH" rehash 2>&1 || true
        start_services || true
        die "Asset activation failed - rolled back to previous version"
    fi

    if [ -f "${INSTALL_DIR}/php_shield.php" ]; then
        echo "Updating PHP Shield..."
        "$BINARY_PATH" install --php-shield-only 2>/dev/null || true
    fi

    if ! "$BINARY_PATH" rehash 2>&1; then
        echo "WARNING: Rehash failed, rolling back..."
        chattr -i "$BINARY_PATH" 2>/dev/null || true
        cp -p "$binary_backup" "$BINARY_PATH"
        rollback_assets "$asset_backup"
        "$BINARY_PATH" rehash 2>&1 || true
        start_services || true
        die "Upgrade failed - rolled back to previous version"
    fi

    if ! start_services; then
        chattr -i "$BINARY_PATH" 2>/dev/null || true
        cp -p "$binary_backup" "$BINARY_PATH"
        rollback_assets "$asset_backup"
        "$BINARY_PATH" rehash 2>&1 || true
        start_services || true
        die "Upgrade failed to start - rolled back to previous version"
    fi
    cleanup_upgrade_backup "$tmpdir"

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
        echo "Continuous Security Monitor - Deploy"
        echo ""
        echo "Usage:"
        echo "  $0 install     Install latest"
        echo "  $0 upgrade     Upgrade to latest"
        echo "  $0 check       Check if update available"
        exit 1
        ;;
esac
