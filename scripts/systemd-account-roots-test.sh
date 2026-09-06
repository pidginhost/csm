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
production=${1:-}
mkdir -p "$artifacts"
printf 'NOT RUN\n' > "$artifacts/result"
: > "$artifacts/service.log"
csm_tags=
service_tags=systemdintegration
if [[ "$production" == production ]]; then
  csm_tags=yara,journal,bpf
  service_tags+=,yara,journal,bpf
  export CGO_ENABLED=1
  export CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)"
fi
go build -tags "$csm_tags" -o "$artifacts/csm" ./cmd/csm
go test -c -race -tags "$service_tags" -o "$artifacts/webui.test" ./internal/webui

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
# Fixed cPanel command fixtures exercise the helper transport, not cPanel itself.
mkdir -p /etc/audit/rules.d /etc/modprobe.d /etc/apache2/conf.d/modsec /etc/apache2/conf-enabled /etc/httpd/conf.d /etc/nginx/conf.d /usr/local/lsws/conf/templates /scripts
getent passwd mailnull >/dev/null || useradd --system --no-create-home mailnull
printf '# operator configuration\n@ROUTERSTART@\n@TRANSPORTSTART@\n' > /etc/exim.conf.local
cat > /scripts/buildeximconf <<'BUILDER'
#!/bin/sh
printf 'rebuild\n' >> /etc/csm-audit-rebuilds
if test -e /var/lib/csm/fail-next-rebuild; then
  rm /var/lib/csm/fail-next-rebuild
  exit 1
fi
BUILDER
chmod 0755 /scripts/buildeximconf
mkdir -p /etc/systemd/system/csm.service.d
cp build/packaging/systemd/csm.service /etc/systemd/system/csm.service
"$artifacts/csm" systemd-roots --config /etc/csm/csm.yaml > /etc/systemd/system/csm.service.d/50-account-roots.conf
cp /etc/systemd/system/csm.service.d/50-account-roots.conf "$artifacts/generated.conf"
cat > /etc/systemd/system/csm.service.d/90-test.conf <<UNIT
[Unit]
Wants=dbus.socket
After=dbus.socket
[Service]
Type=oneshot
ExecStart=
ExecStart=$artifacts/webui.test -test.run=^TestCustomAccountRootsInSystemdService$ -test.v -test.timeout=120s
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
if [[ "$production" == production ]]; then
  mkdir -p /etc/systemd/system/csm-audit.service.d
  cat > /etc/systemd/system/csm-production-kernel.service <<UNIT
[Unit]
Description=CSM production kernel tests
Wants=systemd-journald.service dbus.socket
After=systemd-journald.service dbus.socket csm.service
[Service]
Type=oneshot
TimeoutStartSec=45min
ExecStart=/bin/bash /src/scripts/production-tests.sh kernel
Environment=PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin
Environment=GOPATH=/go
Environment=GOTOOLCHAIN=auto
Environment=GOCACHE=/gocache
Environment=GOMODCACHE=/gomodcache
Environment=GOPROXY=${GOPROXY:-https://proxy.golang.org,direct}
Environment=PKG_CONFIG_PATH=${PKG_CONFIG_PATH:-/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig}
StandardOutput=journal+console
UNIT
  cat > /etc/systemd/system/csm-audit.service.d/production.conf <<UNIT
[Unit]
Wants=csm-production-kernel.service
After=csm-production-kernel.service
UNIT
fi
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
if [[ -f /etc/systemd/system/csm-production-kernel.service ]]; then
  systemctl show csm-production-kernel.service --property=Result,ExecMainStatus > "$artifacts/kernel-properties"
  if [[ "$(systemctl show csm-production-kernel.service --property=Result --value)" != success || "$(systemctl show csm-production-kernel.service --property=ExecMainStatus --value)" != 0 ]]; then
    printf 'FAIL\n' > "$artifacts/result"
    status=1
  fi
  journalctl -u csm-production-kernel.service --no-pager > "$artifacts/kernel-journal.log"
fi
journalctl -u csm.service --no-pager > "$artifacts/journal.log"
# Tests have stopped and their artifacts are closed. EL8's orderly exit target
# can restart itself through SuccessAction=exit until its start limit is hit.
systemctl --force exit "$status"
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
