# Upgrading

## deploy.sh (recommended)

```bash
/opt/csm/deploy.sh upgrade
```

This will:
1. Stop the daemon
2. Back up the current binary
3. Download the new version
4. Verify SHA256 checksum
5. Extract UI assets and rules
6. Rehash config
7. Restart the daemon

Rolls back automatically on failure.

## Troubleshooting

**"store: opening bbolt: timeout"** -- Commands that need live daemon state now route through the control socket at `/var/run/csm/control.sock` and no longer open the database directly, so this error should only appear from `csm baseline`, `csm firewall ...`, or the `check-*` dry-run commands (the remaining in-process paths; see the roadmap for the phase-2 migration). If you hit it from one of those:

- A `csm baseline`, `csm scan`, or `csm check-deep` command is still running
- The daemon was killed uncleanly (SIGKILL, OOM) and the lock file is stale

Fix: check if a CSM process is running (`pgrep csm`). If not, remove the stale lock:
```bash
rm -f /var/lib/csm/state/csm.lock
systemctl start csm
```

**"csm: daemon not running"** -- CLI commands that talk to the daemon (`csm run-critical`, `csm run-deep`, `csm status`) exit 2 with this message when the control socket is missing. Start the daemon with `systemctl start csm`. Bootstrap commands that run before the daemon exists (`csm install`, `csm validate`, `csm verify`, `csm rehash`) do not require it.

**Never delete `csm.db`** -- it contains all historical findings, firewall state, email forwarder baselines, and per-account data. If you delete it, the web UI will show empty data until the next full scan cycle (up to 60 minutes for deep scan findings). If you must reset, use `csm baseline` instead.

**Config changes require rehash** -- After editing `csm.yaml`, run `csm rehash` twice (the config hash is stored inside the config file, creating a circular dependency -- the second run stabilizes it). Or just restart via `systemctl restart csm`.

## RPM/DEB

```bash
yum update csm              # RPM
dpkg -i csm_NEW.deb         # DEB
```

Package managers handle stop/start automatically.

## FHS migration (legacy installs upgrading past v2.11.0)

The packaged layout has moved:

| Concern | Legacy path | New (FHS) path |
|---|---|---|
| Main config | `/opt/csm/csm.yaml` | `/etc/csm/csm.yaml` |
| Drop-in fragments | n/a | `/etc/csm/conf.d/*.yaml` |
| State directory | `/opt/csm/state` | `/var/lib/csm/state` |
| Shipped profiles | n/a | `/usr/lib/csm/profiles` |
| Binary | `/opt/csm/csm` | `/opt/csm/csm` (unchanged) |

The package postinstall creates the FHS directories with the right ownership. The daemon copies a non-empty legacy `/opt/csm/state/` into the new state directory on first start, but only when the new directory is empty (so a partial migration cannot corrupt it). The legacy directory is left in place; remove it after you have verified the new install.

Operators upgrading by **manual binary swap** (without re-running the package postinstall) keep the legacy paths and the daemon will continue using them — `state_path: /opt/csm/state` in the existing `csm.yaml` pins it. To move to the FHS layout, either reinstall the package or create the directories by hand and remove the `state_path:` override.

## systemd `Type=notify` drop-in

The packaged unit file is `Type=notify` with `WatchdogSec=300`. The daemon signals `READY=1` after watchers attach and pings `WATCHDOG=1` on schedule, so `systemctl is-active` reflects truth and the watchdog kills a hung daemon.

Older units shipped `Type=simple`. The watchdog still functions — the daemon pings regardless of unit type — but `systemctl status` only sees the process, not "watchers attached." If you need the new behavior on an older unit, drop in:

```ini
# /etc/systemd/system/csm.service.d/notify.conf
[Service]
Type=notify
NotifyAccess=main
```

Then `systemctl daemon-reload && systemctl restart csm`. Verify with `systemctl show csm -p Type -p StatusText`.

## Auto-response dry-run safety default

`auto_response.dry_run` defaults to `true` when the key is absent. The daemon records every IP it would have blocked but does not touch nftables. If your `auto_response:` block sets `enabled: true` and `block_ips: true` but does **not** set `dry_run`, **add `dry_run: false` explicitly** before relying on auto-block. Verify with:

```bash
csm status --json | jq '.capabilities, .severities'
csm firewall status            # check that "Recently Blocked" picks up new entries after the restart
```

Manual `csm firewall ...` operations bypass dry-run and always apply.
