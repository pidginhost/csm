#!/usr/bin/env bash
set -euo pipefail

# cPanel is the primary target, so a release either exercises it or records
# that it did not. CSM_RELEASE_WITHOUT_CPANEL carries the operator's reason and
# must be a sentence, not a flag, so the omission is legible in release
# evidence rather than hidden behind a "1".
if [ -n "${CI_COMMIT_TAG:-}" ] && [ -z "${INTEGRATION_CPANEL_IMAGE:-}" ]; then
    waiver="${CSM_RELEASE_WITHOUT_CPANEL:-}"
    if [ -z "$waiver" ]; then
        echo "ERROR: release requires INTEGRATION_CPANEL_IMAGE, or CSM_RELEASE_WITHOUT_CPANEL stating why it is unavailable; see docs/src/cpanel-release-tests.md" >&2
        exit 1
    fi
    if [ "${#waiver}" -lt 12 ]; then
        echo "ERROR: CSM_RELEASE_WITHOUT_CPANEL must state why cPanel coverage is unavailable" >&2
        exit 1
    fi
    echo "NOTICE: releasing WITHOUT cPanel coverage: ${waiver}" >&2
    echo "NOTICE: WHM plugin installation, mail integration, platform paths and upgrade behaviour are NOT validated by this pipeline" >&2
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
