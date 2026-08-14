#!/usr/bin/env bash
# ci-delete-server.sh -- delete cloud test servers and confirm they are gone.
#
# Usage: ci-delete-server.sh <server-id>...
#
# A delete issued while a server is still provisioning is accepted by the API
# but loses the race with the build: provisioning finishes afterwards and leaves
# the server running, so the reported success is not worth trusting. Retry until
# the server no longer appears in the account listing. A survivor consumes the
# account's server capacity, which makes every create in the next run fail.

set -uo pipefail

PHCTL="${PHCTL:-phctl}"
DELETE_ATTEMPTS="${CSM_DELETE_ATTEMPTS:-10}"
DELETE_INTERVAL="${CSM_DELETE_INTERVAL:-15}"

# 0 = present, 1 = gone, 2 = listing unavailable.
server_state() {
    local id="$1" listing
    listing=$("$PHCTL" compute server list 2>/dev/null) || return 2
    printf '%s\n' "$listing" | awk -v id="$id" '$1 == id { found = 1 } END { exit !found }'
}

delete_server() {
    local id="$1" attempt state verified=false

    for ((attempt = 1; attempt <= DELETE_ATTEMPTS; attempt++)); do
        "$PHCTL" compute server delete "$id" -f >/dev/null 2>&1 || true

        server_state "$id"
        state=$?
        if [ "$state" -eq 1 ]; then
            echo "server $id deleted (attempt $attempt)"
            return 0
        fi
        [ "$state" -eq 0 ] && verified=true

        [ "$attempt" -lt "$DELETE_ATTEMPTS" ] && sleep "$DELETE_INTERVAL"
    done

    if $verified; then
        echo "ERROR: server $id still present after $DELETE_ATTEMPTS delete attempts -- delete it manually" >&2
    else
        echo "ERROR: cannot verify whether server $id was deleted -- check the account and delete it manually" >&2
    fi
    return 1
}

rc=0
for id in "$@"; do
    [ -n "$id" ] || continue
    delete_server "$id" || rc=1
done
exit "$rc"
