#!/usr/bin/env bash
set -euo pipefail

if [ -n "${CI_COMMIT_TAG:-}" ] && [ -z "${INTEGRATION_CPANEL_IMAGE:-}" ]; then
    echo "ERROR: release requires INTEGRATION_CPANEL_IMAGE; see docs/src/cpanel-release-tests.md" >&2
    exit 1
fi
if [ -n "${INTEGRATION_CPANEL_IMAGE:-}" ] && ! [[ "$INTEGRATION_CPANEL_IMAGE" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
    echo "ERROR: INTEGRATION_CPANEL_IMAGE must be an image ID or slug" >&2
    exit 1
fi
if [ -n "${INTEGRATION_CPANEL_PACKAGE:-}" ] && ! [[ "$INTEGRATION_CPANEL_PACKAGE" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
    echo "ERROR: INTEGRATION_CPANEL_PACKAGE must be a package ID or slug" >&2
    exit 1
fi
if [ -n "${INTEGRATION_CPANEL_IMAGE:-}" ]; then
    if ! images=$(phctl compute image list); then
        echo "ERROR: cPanel image inventory is unavailable" >&2
        exit 1
    fi
    if ! awk -v target="$INTEGRATION_CPANEL_IMAGE" '
        NR == 1 { header = ($1 == "ID" && $NF == "SLUG"); next }
        $1 ~ /^[0-9]+$/ && ($1 == target || $NF == target) { found = 1 }
        END { exit !(header && found) }
    ' <<< "$images"; then
        echo "ERROR: required cPanel image is unavailable to the CI account" >&2
        exit 1
    fi
fi
