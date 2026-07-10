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
    local version="$1" tmpdir="$2"

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

    echo "Verifying SHA256 checksum..." >&2
    verify_checksum "${tmpdir}/${ARTIFACT_NAME}" "${tmpdir}/${ARTIFACT_NAME}.sha256"
    echo "Checksum OK" >&2

    verify_signature "${tmpdir}/${ARTIFACT_NAME}" "$(get_download_url "${ARTIFACT_NAME}.sig" "$version")"

    chmod +x "${tmpdir}/${ARTIFACT_NAME}"
    if ! "${tmpdir}/${ARTIFACT_NAME}" version > /dev/null 2>&1; then
        rm -rf "$tmpdir"
        die "Downloaded binary failed to execute."
    fi

    echo "Downloaded: $("${tmpdir}/${ARTIFACT_NAME}" version)" >&2
}

verify_checksum() {
    local file="$1" checksum_file="$2"
    local expected actual
    expected=$(awk '{print $1}' "$checksum_file")
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
        die "CHECKSUM VERIFICATION FAILED for $(basename "$file")
  Expected: ${expected}
  Got:      ${actual}"
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
    mkdir -p "$backup" "${backup}/rules" "${backup}/activated-rules"
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
        # Mark the rule before overwriting it so rollback also removes a
        # partially written new file when cp fails.
        : > "${backup}/activated-rules/${file}" || return 1
        cp "${INSTALL_DIR}/configs/${file}" "${INSTALL_DIR}/rules/${file}" || return 1
    done
}

# Last-resort recovery: every step is individually guarded so one failure
# cannot abort the script mid-restore under errexit.
rollback_assets() {
    local stage="$1" backup="$2" entry file rollback_status=0
    for entry in ui configs pam deploy.sh; do
        # An entry still in the stage was never activated, so the live copy
        # (if any) is the previous release - leave it in place.
        if [ ! -e "${stage}/${entry}" ] && [ ! -L "${stage}/${entry}" ]; then
            if ! rm -rf "${INSTALL_DIR:?}/${entry}" 2>/dev/null; then
                echo "WARNING: could not remove ${INSTALL_DIR}/${entry} during rollback" >&2
                rollback_status=1
            fi
        fi
        if [ -e "${backup}/${entry}" ] || [ -L "${backup}/${entry}" ]; then
            if [ -e "${INSTALL_DIR}/${entry}" ] || [ -L "${INSTALL_DIR}/${entry}" ]; then
                echo "WARNING: could not restore ${entry} because the live path still exists" >&2
                rollback_status=1
            elif ! mv "${backup}/${entry}" "${INSTALL_DIR}/${entry}" 2>/dev/null; then
                echo "WARNING: could not restore ${entry} during rollback" >&2
                rollback_status=1
            fi
        fi
    done
    for file in malware.yml malware.yar; do
        if [ -f "${backup}/activated-rules/${file}" ]; then
            if ! rm -f "${INSTALL_DIR}/rules/${file}" 2>/dev/null; then
                echo "WARNING: could not remove rules/${file} during rollback" >&2
                rollback_status=1
            fi
            if [ -f "${backup}/rules/${file}" ] && \
                ! cp -p "${backup}/rules/${file}" "${INSTALL_DIR}/rules/${file}" 2>/dev/null; then
                echo "WARNING: could not restore rules/${file} during rollback" >&2
                rollback_status=1
            fi
        fi
    done
    return "$rollback_status"
}

cleanup_upgrade_backup() {
    rm -rf "$1"
}

# Runs in do_upgrade scope: binary_backup, assets_stage, asset_backup,
# binary_was_immutable and tmpdir are the caller's locals.
rollback_upgrade() {
    local reason="$1" rollback_status=0
    # Recovery can itself be interrupted or fail unexpectedly. Preserve the
    # package and backups from the moment rollback begins.
    trap - EXIT
    echo "WARNING: ${reason}; rolling back..." >&2
    chattr -i "$BINARY_PATH" 2>/dev/null || true
    if ! cp -p "$binary_backup" "$BINARY_PATH" 2>/dev/null; then
        echo "WARNING: could not restore previous binary from ${binary_backup}" >&2
        rollback_status=1
    fi
    rollback_assets "$assets_stage" "$asset_backup" || rollback_status=1
    if ! "$BINARY_PATH" rehash 2>&1; then
        echo "WARNING: could not rehash the restored release" >&2
        rollback_status=1
    fi
    # The restored binary's rehash predates config-driven immutability, so
    # re-arm from the state observed before the upgrade.
    if [ "$binary_was_immutable" = "1" ]; then
        if ! chattr +i "$BINARY_PATH" 2>/dev/null; then
            echo "WARNING: could not restore the binary's immutable flag" >&2
            rollback_status=1
        fi
    elif ! chattr -i "$BINARY_PATH" 2>/dev/null; then
        echo "WARNING: could not restore the binary's writable state" >&2
        rollback_status=1
    fi
    if ! start_services; then
        rollback_status=1
    fi
    echo "Rollback material kept at ${tmpdir}" >&2
    if [ "$rollback_status" -ne 0 ]; then
        die "${reason} - rollback incomplete; inspect the warnings above"
    fi
    die "${reason} - rolled back to previous version"
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

    if [ -e "$BINARY_PATH" ] || [ -L "$BINARY_PATH" ]; then die "CSM is already installed. Run: $0 upgrade"; fi

    echo "=== Continuous Security Monitor - Install ==="
    echo ""

    local release_tag
    release_tag=$(resolve_release_tag)

    local tmpdir
    mkdir -p "$INSTALL_DIR"
    tmpdir=$(mktemp -d -p "$INSTALL_DIR")
    trap "rm -rf \"${tmpdir}\"" EXIT
    download_package "$release_tag" "$tmpdir"

    local assets_stage asset_backup
    assets_stage=$(download_and_stage_assets "$release_tag" "$tmpdir")
    asset_backup="${tmpdir}/asset-backup"

    mkdir -p "$INSTALL_DIR"
    if ! cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"; then
        rm -f "$BINARY_PATH" 2>/dev/null || true
        die "Binary installation failed"
    fi
    if ! chmod 0700 "$BINARY_PATH"; then
        rm -f "$BINARY_PATH" 2>/dev/null || true
        die "Could not secure installed binary"
    fi
    if ! activate_assets "$assets_stage" "$asset_backup"; then
        rollback_assets "$assets_stage" "$asset_backup" || true
        rm -f "$BINARY_PATH"
        die "Asset installation failed"
    fi

    if ! "$BINARY_PATH" install; then
        rollback_assets "$assets_stage" "$asset_backup" || true
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

    local release_tag
    release_tag=$(resolve_release_tag)

    local tmpdir
    mkdir -p "$INSTALL_DIR"
    tmpdir=$(mktemp -d -p "$INSTALL_DIR")
    trap "rm -rf \"${tmpdir}\"" EXIT
    download_package "$release_tag" "$tmpdir"

    local new_version
    new_version=$("${tmpdir}/${ARTIFACT_NAME}" version)

    if [ "$old_version" = "$new_version" ]; then
        rm -rf "$tmpdir"
        echo "Already running the latest version."
        start_services
        return
    fi

    local assets_stage asset_backup binary_backup
    assets_stage=$(download_and_stage_assets "$release_tag" "$tmpdir")
    asset_backup="${tmpdir}/asset-backup"
    binary_backup="${tmpdir}/${ARTIFACT_NAME}.previous"

    if ! cp -p "$BINARY_PATH" "$binary_backup"; then
        die "Could not back up current binary"
    fi
    stop_services

    local binary_was_immutable=0
    case "$(lsattr "$BINARY_PATH" 2>/dev/null | awk '{print $1}')" in
        *i*) binary_was_immutable=1 ;;
    esac
    chattr -i "$BINARY_PATH" 2>/dev/null || true
    if ! cp "${tmpdir}/${ARTIFACT_NAME}" "$BINARY_PATH"; then
        rollback_upgrade "Binary installation failed"
    fi
    if ! chmod 0700 "$BINARY_PATH"; then
        rollback_upgrade "Could not secure installed binary"
    fi
    if ! activate_assets "$assets_stage" "$asset_backup"; then
        rollback_upgrade "Asset activation failed"
    fi

    if [ -f "${INSTALL_DIR}/php_shield.php" ]; then
        echo "Updating PHP Shield..."
        "$BINARY_PATH" install --php-shield-only 2>/dev/null || true
    fi

    if ! "$BINARY_PATH" rehash 2>&1; then
        rollback_upgrade "Rehash failed"
    fi

    if ! start_services; then
        rollback_upgrade "Daemon failed to start"
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
