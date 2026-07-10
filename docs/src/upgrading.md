# Upgrading

## Package installations (recommended)

Use the same signed repository that installed CSM:

```bash
sudo apt update && sudo apt install --only-upgrade csm   # Debian/Ubuntu
sudo dnf upgrade csm                                     # RHEL family
```

The package preserves the operator config and state, updates runtime assets, re-signs integrity metadata, and restarts the daemon when it was already active.

## Standalone installations

```bash
sudo /opt/csm/deploy.sh upgrade
```

The helper:

1. Downloads and verifies the binary and supporting assets
2. Stages the UI, rules, PAM files, and deploy helper before downtime
3. Stops the daemon and keeps the previous binary and assets as rollback material
4. Activates the staged release and rehashes the config once
5. Restarts the daemon and confirms it is active

If activation, rehash, or startup fails, the helper restores the previous binary and assets, re-signs the restored binary hash, and starts the previous version.

## Troubleshooting

**"store: opening bbolt: timeout"** -- Most operator commands that need live state now route through the control socket at `/var/run/csm/control.sock`. This error should only appear from commands that intentionally open the bbolt file directly, such as `csm store compact`, `csm store import`, `csm store reset-bot-verify`, `csm db-clean --drop-object`, or a second daemon start while one daemon already owns the database.

Fix: stop the daemon before direct-store maintenance commands, then retry:
```bash
systemctl stop csm
csm store compact
systemctl start csm
```

If `systemctl` says CSM is stopped but bbolt still times out, find the process holding `/var/lib/csm/state/csm.db` and stop that process after review. Do not delete `csm.lock`; it is only the daemon instance guard and does not release bbolt's file lock.

**"csm: daemon not running"** -- CLI commands that talk to the daemon exit 2 with this message when the control socket is missing. This includes `csm run*`, `csm check*`, `csm baseline`, `csm status`, `csm firewall ...`, `csm store export`, `csm export --since`, and `csm phprelay ...`. Start the daemon with `systemctl start csm`. Bootstrap commands that run before the daemon exists (`csm install`, `csm validate`, `csm config schema`, `csm verify`, `csm rehash`) do not require it.

**Never delete `csm.db`** -- it contains all historical findings, firewall state, email forwarder baselines, and per-account data. If you delete it, the web UI will show empty data until the next full scan cycle (up to 60 minutes for deep scan findings). Restore from backup when possible; for an intentional reset, run `csm baseline --confirm` rather than removing the database by hand.

**Config changes require rehash** -- After editing a restart-required field in `csm.yaml`, run `csm rehash` once, validate, then restart. Hot-reload-safe changes can use `systemctl reload csm`; the daemon validates and re-signs the accepted config itself.

## FHS migration (state, config, drop-ins, and profiles)

Current packages use FHS paths for state, config, drop-ins, and shipped profiles. Legacy main configs continue to work during the transition.

| Concern | Legacy path | Current path |
|---|---|---|
| Drop-in fragments | n/a | `/etc/csm/conf.d/*.yaml` |
| State directory | `/opt/csm/state` | `/var/lib/csm/state` |
| Shipped profiles | n/a | `/usr/lib/csm/profiles` |
| Binary | `/opt/csm/csm` | `/opt/csm/csm` (unchanged) |
| Main config | `/opt/csm/csm.yaml` | `/etc/csm/csm.yaml` |
| Legacy config path | n/a | `/opt/csm/csm.yaml` symlink |

The package postinstall creates the FHS directories with the right ownership. If `/opt/csm/csm.yaml` is a real file and `/etc/csm/csm.yaml` is absent or still the shipped placeholder, the package copies the legacy config into `/etc/csm/csm.yaml` and then replaces the old path with a symlink. If both paths are real files with different operator content, CSM refuses the implicit default path until you move one aside or pass `--config <path>`.

The daemon copies a non-empty legacy `/opt/csm/state/` into the new state directory on first start, but only when the new directory is empty (so a partial migration cannot corrupt it). The legacy directory is left in place; remove it after you have verified the new install.

Operators upgrading by **manual binary swap** (without re-running the package postinstall) keep the legacy state path if `state_path: /opt/csm/state` is pinned in the existing `csm.yaml`. To move state to the FHS layout, either reinstall the package or create the directories by hand and remove the `state_path:` override.

## systemd `Type=notify` drop-in

The packaged unit file is `Type=notify` with `WatchdogSec=300`. The daemon signals `READY=1` after watchers attach and pings `WATCHDOG=1` on schedule, so `systemctl is-active` reflects truth and the watchdog kills a hung daemon.

Older units shipped `Type=simple`. The watchdog still functions because the daemon pings regardless of unit type, but `systemctl status` only sees the process, not "watchers attached." If you need the new behavior on an older unit, drop in:

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
csm status --json | jq '.auto_response_dry_run, .dry_run_blocks'
csm firewall status            # check that "Recently Blocked" picks up new entries after the restart
```

Manual `csm firewall ...` operations bypass dry-run and always apply.
