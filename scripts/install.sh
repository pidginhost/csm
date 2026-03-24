#!/bin/bash
# cPanel Security Monitor — Bootstrap installer
# Downloads the latest binary and runs csm install
set -euo pipefail

REPO="pidginhost/cpanel-security-monitor"
INSTALL_DIR="/opt/csm"
BINARY="$INSTALL_DIR/csm"
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "=== cPanel Security Monitor — Bootstrap Installer ==="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root"
    exit 1
fi

# Check if already installed
if [ -f "$BINARY" ]; then
    echo "CSM is already installed at $BINARY"
    echo "Current version: $($BINARY version 2>/dev/null || echo 'unknown')"
    echo ""
    read -p "Upgrade? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    # Remove immutable flag for upgrade
    chattr -i "$BINARY" 2>/dev/null || true
fi

# Download latest release
echo "Downloading latest release for linux-${ARCH}..."
LATEST_URL=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep "browser_download_url.*linux-${ARCH}" | head -1 | cut -d '"' -f 4)

if [ -z "$LATEST_URL" ]; then
    echo "Error: could not find download URL. Check https://github.com/${REPO}/releases"
    echo ""
    echo "Manual install:"
    echo "  1. Download the binary for your architecture"
    echo "  2. chmod +x csm-linux-${ARCH}"
    echo "  3. ./csm-linux-${ARCH} install"
    exit 1
fi

mkdir -p "$INSTALL_DIR"
curl -sL "$LATEST_URL" -o "${BINARY}.new"
chmod +x "${BINARY}.new"

# Verify it runs
if ! "${BINARY}.new" version > /dev/null 2>&1; then
    echo "Error: downloaded binary failed to execute"
    rm -f "${BINARY}.new"
    exit 1
fi

mv "${BINARY}.new" "$BINARY"
echo "Downloaded: $($BINARY version)"
echo ""

# Run install
$BINARY install

echo ""
echo "Bootstrap complete!"
