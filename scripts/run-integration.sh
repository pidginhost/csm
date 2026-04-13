#!/usr/bin/env bash
# run-integration.sh — creates cloud servers, runs integration tests, collects coverage.
# Usage: ./scripts/run-integration.sh [--keep-on-fail]
#
# Requires: phctl (authenticated), go, ssh key configured.
# Environment: SSH_KEY_ID (default: 332)

set -euo pipefail

SSH_KEY_ID="${SSH_KEY_ID:-332}"
KEEP_ON_FAIL=false
[ "${1:-}" = "--keep-on-fail" ] && KEEP_ON_FAIL=true

ALMA_ID=""
UBUNTU_ID=""
ALMA_IP=""
UBUNTU_IP=""

cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ] && $KEEP_ON_FAIL; then
        echo ""
        echo "=========================================="
        echo "INTEGRATION TESTS FAILED — servers kept alive"
        [ -n "$ALMA_IP" ] && echo "  AlmaLinux: ssh phuser@${ALMA_IP}"
        [ -n "$UBUNTU_IP" ] && echo "  Ubuntu:    ssh phuser@${UBUNTU_IP}"
        [ -n "$ALMA_ID" ] && echo "  Alma ID:   ${ALMA_ID} — delete with: phctl compute server delete ${ALMA_ID} -f"
        [ -n "$UBUNTU_ID" ] && echo "  Ubuntu ID: ${UBUNTU_ID} — delete with: phctl compute server delete ${UBUNTU_ID} -f"
        echo "=========================================="
        return
    fi
    echo "Cleaning up servers..."
    [ -n "$ALMA_ID" ] && phctl compute server delete "$ALMA_ID" -f 2>/dev/null || true
    [ -n "$UBUNTU_ID" ] && phctl compute server delete "$UBUNTU_ID" -f 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Building integration test binary ==="
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c \
    -tags integration \
    -covermode=atomic \
    -coverpkg=./internal/... \
    -o dist/csm-integ.test \
    ./e2e/
echo "  Built dist/csm-integ.test"

echo ""
echo "=== Creating test servers ==="
ALMA_ID=$(phctl compute server create \
    --image alma9 --package cloudv-0 \
    --hostname csm-integ-alma --ssh-key-id "$SSH_KEY_ID" \
    --new-ipv4 -f 2>&1 | grep -oP 'ID: \K[0-9]+')
echo "  AlmaLinux server: ID=$ALMA_ID"

UBUNTU_ID=$(phctl compute server create \
    --image ubuntu24 --package cloudv-0 \
    --hostname csm-integ-ubuntu --ssh-key-id "$SSH_KEY_ID" \
    --new-ipv4 -f 2>&1 | grep -oP 'ID: \K[0-9]+')
echo "  Ubuntu server: ID=$UBUNTU_ID"

echo "  Waiting for servers to boot..."
sleep 45

ALMA_IP=$(phctl compute ipv4 list 2>/dev/null | grep csm-integ-alma | awk '{print $2}')
UBUNTU_IP=$(phctl compute ipv4 list 2>/dev/null | grep csm-integ-ubuntu | awk '{print $2}')
echo "  AlmaLinux IP: $ALMA_IP"
echo "  Ubuntu IP:    $UBUNTU_IP"

# Clear old host keys
ssh-keygen -R "$ALMA_IP" 2>/dev/null || true
ssh-keygen -R "$UBUNTU_IP" 2>/dev/null || true

SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=30"

echo ""
echo "=== Installing CSM on AlmaLinux ==="
ssh $SSH_OPTS phuser@"$ALMA_IP" "sudo bash -c '
    rpm --import https://mirrors.pidginhost.com/csm/csm-signing.gpg
    cat > /etc/yum.repos.d/csm.repo <<EOF
[csm]
name=CSM
baseurl=https://mirrors.pidginhost.com/csm/rpm/el\\\$releasever/\\\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.pidginhost.com/csm/csm-signing.gpg
EOF
    dnf install -y csm
    /opt/csm/csm version
'" 2>&1 | tail -5

echo ""
echo "=== Installing CSM on Ubuntu ==="
ssh $SSH_OPTS phuser@"$UBUNTU_IP" "sudo bash -c '
    curl -fsSL https://mirrors.pidginhost.com/csm/csm-signing.gpg | gpg --dearmor -o /etc/apt/keyrings/csm.gpg
    echo \"deb [signed-by=/etc/apt/keyrings/csm.gpg] https://mirrors.pidginhost.com/csm/deb stable main\" > /etc/apt/sources.list.d/csm.list
    apt update -qq && apt install -y csm
    /opt/csm/csm version
'" 2>&1 | tail -5

run_tests() {
    local IP=$1
    local NAME=$2
    local COV_FILE="integ-${NAME}.out"

    echo ""
    echo "=== Running integration tests on $NAME ($IP) ==="
    scp $SSH_OPTS dist/csm-integ.test phuser@"$IP":/tmp/csm-integ.test

    ssh $SSH_OPTS phuser@"$IP" "sudo /tmp/csm-integ.test \
        -test.v \
        -test.timeout=300s \
        -test.coverprofile=/tmp/coverage.out \
        2>&1" | tee "dist/integ-${NAME}.log"

    scp $SSH_OPTS phuser@"$IP":/tmp/coverage.out "dist/${COV_FILE}" 2>/dev/null || echo "  (no coverage profile collected)"
    echo "  $NAME: done"
}

run_tests "$ALMA_IP" "alma9"
run_tests "$UBUNTU_IP" "ubuntu24"

echo ""
echo "=== Merging coverage ==="
if command -v gocovmerge >/dev/null 2>&1; then
    PROFILES=""
    [ -f coverage.out ] && PROFILES="coverage.out"
    [ -f dist/integ-alma9.out ] && PROFILES="$PROFILES dist/integ-alma9.out"
    [ -f dist/integ-ubuntu24.out ] && PROFILES="$PROFILES dist/integ-ubuntu24.out"
    if [ -n "$PROFILES" ]; then
        gocovmerge $PROFILES > dist/merged-coverage.out
        go tool cover -func=dist/merged-coverage.out | tail -1
    fi
else
    echo "  gocovmerge not installed — skipping merge"
    echo "  Install: go install github.com/wadey/gocovmerge@latest"
fi

echo ""
echo "=== Integration tests complete ==="
echo "  Logs: dist/integ-alma9.log, dist/integ-ubuntu24.log"
[ -f dist/merged-coverage.out ] && echo "  Merged coverage: dist/merged-coverage.out"
