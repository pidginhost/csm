# Upgrading

Use the signed APT/DNF repository for maintained package upgrades. Standalone
deploy scripts require successful detached signature verification for current
releases. They verify with OpenSSL 3.0+ where available, otherwise with the installed
CSM binary's `csm verify-release`, otherwise with `python3-cryptography`, so
upgrades keep working on EL8/CloudLinux 8 (OpenSSL 1.1.1) including the first
upgrade to a build that provides `csm verify-release`. When no verifier is
present the upgrade stops; disabling `CSM_REQUIRE_SIGNATURES` does not enable
unsigned current upgrades. Set `CSM_VERIFIER_BINARY` to select a specific CSM
binary. See
[Release signing](release-signing.md) for the historical-release exception.

## Package installations (recommended)

Use the same signed repository that installed CSM:

```bash
sudo apt update && sudo apt install --only-upgrade csm   # Debian/Ubuntu
sudo dnf upgrade csm                                     # RHEL family
```

The package preserves the operator config and state, updates runtime assets, re-records integrity hashes, and restarts the daemon when it was already active.

Debian and Ubuntu upgrades keep the local main config without a dpkg prompt. Compare it with the shipped template at `/usr/lib/csm/csm.yaml.default`. RPM keeps a locally modified config and writes a changed template to `/etc/csm/csm.yaml.rpmnew`. RPM may update an unmodified config in place.

If the main config is missing on upgrade and there is no regular legacy config to migrate, package setup stops before restarting CSM. Restore your config to `/etc/csm/csm.yaml` and retry.

## Standalone installations

```bash
sudo /opt/csm/deploy.sh upgrade
```

The upgrade refuses to install a release older than the one running. To roll back deliberately, run it with `CSM_ALLOW_DOWNGRADE=1`.


The helper:

1. Downloads and verifies the binary and supporting assets
2. Stages the UI, rules, PAM files, and deploy helper before downtime
3. Stops the daemon and keeps the previous binary and assets as rollback material
4. Activates the staged release and rehashes the config once
5. Restarts the daemon, checks sustained liveness, and runs `csm doctor`

The health gate waits 20 seconds by default. Set `CSM_UPGRADE_HEALTH_SETTLE` to an integer from 1 to 3600 seconds for a longer or shorter observation window. Invalid values fail the gate. Doctor warnings do not trigger rollback; failed checks do.

If activation, rehash, startup, or the health gate fails, the helper stops the new daemon, restores the previous binary and assets, re-records the restored binary hash, and starts the previous version. It exits nonzero and reports where it retained recovery material. If recovery itself fails, it reports an incomplete rollback that needs operator attention.

## Optional nightly upgrades

Packages ship a disabled sample at `/opt/csm/configs/cron/csm-auto-upgrade`. It runs only after an operator installs it into `/etc/cron.d/`:

```bash
csm version && /opt/csm/deploy.sh check
sudo install -m 0644 /opt/csm/configs/cron/csm-auto-upgrade /etc/cron.d/csm-auto-upgrade
```

Confirm the host runs a published release first. The checksum check reports any different build as an available update. The downgrade guard rejects a lower version, but a development build with the same version can still be replaced by the published release.

The job invokes the standalone deploy helper every night between 03:30 and 04:30, with a random delay and a nonblocking lock. This updates runtime files directly; it does not update APT/DNF's installed package version. Hosts that need package-manager ownership and version tracking should use their package upgrade automation instead.

Output goes to `/var/log/csm/auto-upgrade.log`. Failures also produce cron mail to root; configure and test root's mail alias before enabling the job. This notification does not depend on CSM's alert channels or on successful daemon recovery. Successful runs and an already-held lock produce no mail. Staggering spreads upgrades over an hour but does not stop a bad release from reaching the fleet.

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

**Config changes require rehash** -- After editing a restart-required field in `csm.yaml` or any conf.d drop-in, run `csm rehash` once, validate, then restart. Hot-reload-safe changes can use `systemctl reload csm`; the daemon validates the accepted config and re-records its hash itself. A restart that fails with `conf.d hash mismatch` means a drop-in changed since the hashes were last recorded: rehash if the change was intentional, and list fragments an integration rewrites on its own under `confd.integrity_exempt` so they stop needing one. `csm doctor` reports the mismatch while the daemon is still up.

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

The package postinstall creates the FHS directories with the right ownership. If `/opt/csm/csm.yaml` is a real file and `/etc/csm/csm.yaml` is absent or still the shipped placeholder, the package copies the legacy config into `/etc/csm/csm.yaml` and then replaces the old path with a symlink. If both paths are real files with different operator content, CSM refuses the implicit default path until you move one aside or pass `--config <path>`. Copies that differ only in the `integrity` hashes CSM writes itself (`binary_hash`, `config_hash`, `confd_hash`) are treated as the same configuration: the daemon starts from `/etc/csm/csm.yaml`, and the next `csm rehash` replaces the legacy copy with the symlink.

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

The first disabled queued response raises admission state to schema 10,
which older binaries that read only schema 9 cannot open; they keep blocking
with the legacy budget. While admission only previews and forecasts, it
creates no genuine charge, attempt or unknown hold beyond the state legacy
blocking keeps. Preview accounting is not enforcement state. This is not a
downgrade guard for a ledger that has executed real actions. Never delete the
state database or replace it with an older copy to get past the format check.

The first positive elapsed episode end this release records raises
admission state to schema 13, including on hosts that only preview or
forecast. Older binaries cannot open it and keep blocking with the legacy
budget, as above. Roll back only to a build that supports both schema 13
and elapsed episode records.

A live admission ledger records each episode's latest verified block and
retains a verified episode's boundary even after an unattempted return is
forgotten. The first verified block raises the ledger to schema 15. Roll
back only to a build that reads schema 15, understands the recorded
verified generation, and retains and cleans up these rows; older builds
refuse this ledger. This
writer runs only on hosts where admission executes. Keep the database when changing binaries.

After live re-admissions, roll back only to a build that also keeps the
original verified boundary and caps queued returns at it. A build that
only reads the format can give an old queued return a full lifetime.
Stop the daemon before replacing the binary and keep the database.

`auto_response.dry_run` defaults to `true` when the key is absent. Automatic IP blocks are not applied. With the firewall on outside observe mode, the dry-run count holds retained forecast examples, including older entries until pruning; it is not active occupancy or a count of all attempted blocks. If your `auto_response:` block sets `enabled: true` and `block_ips: true` but does **not** set `dry_run`, **add `dry_run: false` explicitly** before relying on auto-block. Verify with:

```bash
csm status --json | jq '.auto_response_dry_run, .dry_run_blocks'
csm firewall status            # check that "Recently Blocked" picks up new entries after the restart
```

Manual `csm firewall ...` operations bypass dry-run and always apply.

## Admission applies automatic IP blocks

From this release, a host with `auto_response.dry_run: false`, the firewall
on and outside observe mode applies automatic IP blocks through admission,
within its hourly ceiling and the free slots of the temporary set. A host
that already runs with `dry_run: false` does so from the first start of the
new build. To check the admission comparison first, set `dry_run: true`
before the upgrade, compare a dry-run window as described in
[finding streams](finding-streams.md#comparing-the-admission-preview), and
set `dry_run: false` once it passes.

Legacy blocks applied before the upgrade stay until they expire. When
admission wants a longer block for an address such a block already holds,
the work waits for that block to end. For Critical work the wait raises a
capacity notice with reason `pending_recovery`; the legacy block keeps the
address blocked meanwhile.

The automatic block counter now also counts the challenge, central and
incident blocks admission applies, so block rates on dashboards can rise
after the upgrade.

To stop admission applying blocks without changing the binary, set
`auto_response.dry_run: true` and run `systemctl reload csm`. Dry run stops
every automatic IP block, legacy ones included; blocks already applied stay
until they expire. To return automatic blocking to the legacy path, roll
back the binary instead.

The supported rollback target is the pre-flip 4.14.0 release. Older builds
cannot safely read all admission records; some also reject newer config
keys. Removing config keys does not make those versions safe rollback
targets. Keep the database and firewall state, including action identifiers
and absolute expiries. Do not restore an older state snapshot to bypass a
format check.

Before upgrading, retain a verified 4.14.0 package or release artifact and
its matching assets; also retain the new artifact for recovery. The upgrade
helper deletes its previous-binary copy after a successful upgrade. Resolve
the active config and state locations, including drop-ins, and keep a
restricted backup.

For a rollback:

1. Set `auto_response.dry_run: true` in the effective configuration, reload,
   and confirm `csm status --json` reports `auto_response_dry_run: true`.
   A drop-in may override the main config. Confirm admission has stopped
   executing (`admission.owner.executing` is false) before
   proceeding; a failed reload is not a successful stop.
2. Note the installed version, the `csm doctor` result and the current
   timed blocks, then stop `csm.service` and confirm it is inactive.
   Keep a consistent backup of the stopped database and firewall state.
3. Install the retained 4.14.0 package with the package manager, allowing
   the downgrade. The standalone helper installs only the latest release:
   on a standalone host, put the retained 4.14.0 binary and its assets in
   place and run `csm rehash` before starting. Do not substitute a locally
   compiled binary.
4. Start the service if the installer did not, verify the running version,
   sustained service health and `csm doctor`, and compare remaining timed
   blocks and expiries with the saved inventory. Keep dry run enabled until
   these checks pass. Version 4.14.0 only previews admission; with dry run
   off, the legacy path applies automatic blocks.
5. To resume legacy automatic blocking, set `auto_response.dry_run: false`,
   reload and verify the effective status. Leaving it true continues to
   suppress automatic blocking. Existing blocks retain their expiry; this
   procedure does not flush them or promise to restore already expired
   blocks.

If installation or health checks fail, keep dry run enabled and restore the
retained verified new release and its matching assets through the same
workflow. Rehash if required, start and repeat the health and block checks.
Keep current state in place; recover a damaged state backup only through
the documented backup/restore procedure. Do not re-enable automatic blocks
on a failed health check.

Admission starts live once per ledger. Upgrading again after a rollback
does not repeat that start: blocks the legacy path applied in the meantime
stay until they expire, and the legacy path's hour is not carried over
into admission's hourly ceiling. To compare a dry-run window again before
admission blocks, keep `auto_response.dry_run: true` through the upgrade.
