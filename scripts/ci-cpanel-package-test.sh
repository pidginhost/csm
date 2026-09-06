#!/usr/bin/env bash
# Run only on the disposable cPanel VM provisioned by the integration job.
set -euo pipefail
[ "${CSM_CPANEL_TEST_SERVER:-}" = 1 ] || { echo "ERROR: disposable cPanel test marker required" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "ERROR: test requires root" >&2; exit 1; }
[ "$#" = 3 ] || { echo "ERROR: expected candidate RPM, baseline RPM, candidate binary SHA-256" >&2; exit 1; }
candidate=$1
baseline=$2
expected=$3
[[ "$expected" =~ ^[a-f0-9]{64}$ ]] || { echo "ERROR: invalid candidate binary hash" >&2; exit 1; }
test -x /usr/local/cpanel/cpanel
test ! -e /opt/csm/csm
test ! -e /etc/csm/csm.yaml
test ! -e /var/lib/csm
/usr/local/cpanel/cpanel -V
uname -a
if rpm -q csm >/dev/null 2>&1; then
    echo "ERROR: image already contains CSM" >&2
    exit 1
fi

collect() {
    journalctl -u csm.service --no-pager > /tmp/cpanel-csm-journal.log || true
    systemctl show csm.service -p Type -p ProtectSystem -p ReadWritePaths -p Result -p MainPID > /tmp/cpanel-csm-service.txt || true
}
trap collect EXIT

# The baseline is a published, checksum-pinned RPM; the candidate comes from
# this pipeline before signing/publication. Neither is resolved from a mirror.
dnf install -y --nogpgcheck "$baseline"
cat > /etc/csm/conf.d/99-integration.yaml <<'CONFIG'
alerts:
  email:
    enabled: false
  webhook:
    enabled: false
auto_response:
  enabled: false
  dry_run: true
mail_logs:
  source: file
updates:
  check_enabled: false
CONFIG
printf '\n# CSM integration operator setting\n' >> /etc/csm/csm.yaml
/opt/csm/csm rehash
systemctl start csm.service
/opt/csm/csm status --json > /tmp/cpanel-baseline-status.json
systemctl stop csm.service
printf 'preserve across package upgrade\n' > /var/lib/csm/state/integration-sentinel
config_before=$(sha256sum /etc/csm/csm.yaml)
dropin_before=$(sha256sum /etc/csm/conf.d/99-integration.yaml)

# Keep the service running so the RPM upgrade must restart it successfully.
systemctl start csm.service
dnf install -y --nogpgcheck "$candidate"
[ "$config_before" = "$(sha256sum /etc/csm/csm.yaml)" ]
[ "$dropin_before" = "$(sha256sum /etc/csm/conf.d/99-integration.yaml)" ]
grep -Fxq 'preserve across package upgrade' /var/lib/csm/state/integration-sentinel
printf '%s  /opt/csm/csm\n' "$expected" | sha256sum --check --status
systemctl is-active --quiet csm.service

# Exercise the candidate's cPanel installer as well as the RPM upgrade path.
/opt/csm/csm install --package-mode
[ "$config_before" = "$(sha256sum /etc/csm/csm.yaml)" ]
[ "$dropin_before" = "$(sha256sum /etc/csm/conf.d/99-integration.yaml)" ]
/opt/csm/csm rehash
systemctl restart csm.service
/opt/csm/csm validate
/tmp/csm-cpanel.test -test.v -test.timeout=10m
/opt/csm/csm status --json > /tmp/cpanel-candidate-status.json
printf 'CPANEL_CANDIDATE_PACKAGE_PASS\n'
