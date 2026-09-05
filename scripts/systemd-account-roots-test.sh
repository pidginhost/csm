#!/usr/bin/env bash
# Boot only through scripts/go-linux.sh with a systemd-equipped Go image.
# This replaces PID 1 in a disposable container; never run it on a host.
set -euo pipefail
if [[ "$(uname -s)" != Linux || $$ != 1 || ! -e /src/.git || ! -d /gocache || ! -d /gomodcache ]]; then
  printf 'Run this script as PID 1 through scripts/go-linux.sh in a disposable Linux container.\n' >&2
  exit 1
fi
cd /src
artifacts=/src/.cache/systemd-account-roots
mkdir -p "$artifacts"
printf 'NOT RUN\n' > "$artifacts/result"
: > "$artifacts/service.log"
go build -o "$artifacts/csm" ./cmd/csm
go test -c -race -tags systemdintegration -o "$artifacts/webui.test" ./internal/webui

# A separate filesystem exercises mount ordering and the grant for custom
# content without making an unconfigured sibling writable.
volume=/srv/csm-audit-volume
content="$volume/accounts/alice/public"
outside=/srv/csm-audit-outside
mkdir -p "$volume" "$outside"
mount -t tmpfs tmpfs "$volume"
mkdir -p "$content"
chown 1001:1002 "$volume/accounts/alice" "$content"
printf untouched > "$outside/guard"
mkdir -p /etc/csm/conf.d /opt/csm/quarantine /opt/csm/policies /opt/csm/rules /var/lib/csm /var/log/csm
cat > /etc/csm/csm.yaml <<CONFIG
hostname: service-test
state_path: /var/lib/csm/state
alerts:
  email:
    enabled: true
    to: [operator@example.test]
    from: csm@example.test
    smtp: localhost:25
account_roots:
  - $content
CONFIG
mkdir -p /etc/systemd/system/csm.service.d
cp build/packaging/systemd/csm.service /etc/systemd/system/csm.service
"$artifacts/csm" systemd-roots --config /etc/csm/csm.yaml > /etc/systemd/system/csm.service.d/50-account-roots.conf
cp /etc/systemd/system/csm.service.d/50-account-roots.conf "$artifacts/generated.conf"
cat > /etc/systemd/system/csm.service.d/90-test.conf <<UNIT
[Service]
Type=oneshot
ExecStart=
ExecStart=$artifacts/webui.test -test.run=^TestCustomAccountRootsInSystemdService$ -test.v -test.timeout=60s
ExecReload=
Restart=no
WatchdogSec=0
Environment=CSM_TEST_ACCOUNT_ROOT=$content
Environment=CSM_TEST_OUTSIDE_ROOT=$outside
Environment=CSM_TEST_RULES_DIR=/src/configs
Environment=CSM_TEST_BINARY=$artifacts/csm
Environment=CSM_TEST_CONFIG=/etc/csm/csm.yaml
StandardOutput=file:$artifacts/service.log
StandardError=inherit
UNIT
cat > "$artifacts/finish.sh" <<'FINISH'
#!/bin/bash
set -euo pipefail
artifacts=/src/.cache/systemd-account-roots
systemctl show csm.service --property=Result,ExecMainStatus,ReadWritePaths,ProtectSystem > "$artifacts/properties"
if [[ "$(systemctl show csm.service --property=Result --value)" == success && "$(systemctl show csm.service --property=ExecMainStatus --value)" == 0 ]] &&
  grep -q '^--- PASS: TestCustomAccountRootsInSystemdService (' "$artifacts/service.log"; then
  printf 'PASS\n' > "$artifacts/result"
  status=0
else
  printf 'FAIL\n' > "$artifacts/result"
  status=1
fi
journalctl -u csm.service --no-pager > "$artifacts/journal.log"
systemctl exit "$status"
FINISH
cat > /etc/systemd/system/csm-audit.service <<UNIT
[Unit]
Description=Collect isolated CSM service test results
Wants=csm.service
After=csm.service
[Service]
Type=oneshot
ExecStart=/bin/bash $artifacts/finish.sh
UNIT
exec env container=other /lib/systemd/systemd --system --unit=csm-audit.service --log-target=console
