#!/usr/bin/env bash
# ci-delete-server.sh -- delete cloud test servers and confirm they are gone.
#
# Usage: ci-delete-server.sh <server-id>...
#
# A delete issued while a server is still provisioning is accepted by the API
# but loses the race with the build: provisioning finishes afterwards and leaves
# the server running, so the reported success is not worth trusting. Monitor the
# full retry window and delete the server again if it reappears. A survivor
# consumes the account's server capacity, which makes every create in the next
# run fail.

set -uo pipefail

PHCTL="${PHCTL:-phctl}"
DELETE_ATTEMPTS="${CSM_DELETE_ATTEMPTS:-10}"
DELETE_INTERVAL="${CSM_DELETE_INTERVAL:-15}"

if [[ ! "$DELETE_ATTEMPTS" =~ ^([2-9]|[1-9][0-9]+)$ ]]; then
    echo "ERROR: CSM_DELETE_ATTEMPTS must be an integer of at least 2" >&2
    exit 1
fi
if [[ ! "$DELETE_INTERVAL" =~ ^(0|[1-9][0-9]*)$ ]]; then
    echo "ERROR: CSM_DELETE_INTERVAL must be a non-negative integer" >&2
    exit 1
fi

# 0 = present, 1 = gone, 2 = listing unavailable.
server_state() {
    local id="$1" listing
    listing=$("$PHCTL" compute server list 2>/dev/null) || return 2
    printf '%s\n' "$listing" |
        awk -v id="$id" '$1 ~ /^[1-9][0-9]*$/ && ($1 "#") == (id "#") { found = 1 } END { exit !found }'
}

delete_server() {
    local id="$1" attempt state
    local delete_pending=true
    local gone_polls=0
    local delete_attempts=0

    for ((attempt = 1; attempt <= DELETE_ATTEMPTS; attempt++)); do
        if $delete_pending; then
            "$PHCTL" compute server delete "$id" -f >/dev/null 2>&1 || true
            ((delete_attempts += 1))
        fi

        server_state "$id"
        state=$?
        if [ "$state" -eq 1 ]; then
            delete_pending=false
            ((gone_polls += 1))
        else
            # Unknown is not gone. Retry the delete after either a positive
            # sighting or a listing failure, then verify again.
            delete_pending=true
            gone_polls=0
        fi

        if [ "$attempt" -lt "$DELETE_ATTEMPTS" ]; then
            sleep "$DELETE_INTERVAL"
        fi
    done

    # Do not return on the first absence: an in-flight provisioner can restore
    # the server later. It must also be absent on the next scheduled poll.
    if [ "$state" -eq 1 ] && [ "$gone_polls" -ge 2 ]; then
        echo "server $id deleted ($delete_attempts delete requests)"
        return 0
    fi

    if [ "$state" -eq 0 ]; then
        echo "ERROR: server $id still present after $delete_attempts delete requests -- delete it manually" >&2
    else
        echo "ERROR: cannot verify whether server $id was deleted -- check the account and delete it manually" >&2
    fi
    return 1
}

rc=0
pids=()
for id in "$@"; do
    [ -n "$id" ] || continue
    if [[ ! "$id" =~ ^[1-9][0-9]*$ ]]; then
        echo "ERROR: invalid server id: $id" >&2
        rc=1
        continue
    fi
    delete_server "$id" &
    pids+=("$!")
done
for pid in "${pids[@]}"; do
    wait "$pid" || rc=1
done
exit "$rc"
