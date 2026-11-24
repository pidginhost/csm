# Upgrading

Use the signed APT/DNF repository for maintained package upgrades. A standalone install upgrades with the deploy helper, which verifies the release signature before it installs anything. Before you upgrade a host that blocks addresses automatically, read [Auto-response dry-run safety default](#auto-response-dry-run-safety-default) and [Admission applies automatic IP blocks](#admission-applies-automatic-ip-blocks).

## Package installations (recommended)

Use the same signed repository that installed CSM:

```bash
sudo apt update && sudo apt install --only-upgrade csm   # Debian/Ubuntu
sudo dnf upgrade csm                                     # RHEL family
```

The package does four things:

- It preserves the operator config and state.
- It updates runtime assets.
- It re-records integrity hashes.
- It restarts the daemon when the daemon was already active.

### What happens to your config file

| Package | Main config on upgrade |
|---------|------------------------|
| Debian and Ubuntu | The upgrade keeps the local main config without a dpkg prompt. Compare it with the shipped template at `/usr/lib/csm/csm.yaml.default`. |
| RPM | RPM keeps a locally modified config and writes a changed template to `/etc/csm/csm.yaml.rpmnew`. It may update an unmodified config in place. |

If the main config is missing on upgrade and there is no regular legacy config to migrate, package setup stops before restarting CSM. Restore your config to `/etc/csm/csm.yaml` and retry.

## Standalone installations

```bash
sudo /opt/csm/deploy.sh upgrade
```

The upgrade refuses to install a release older than the one running. To roll back deliberately, run it with `CSM_ALLOW_DOWNGRADE=1`.

### What the helper does

1. Downloads and verifies the binary and supporting assets
2. Stages the UI, rules, PAM files, and deploy helper before downtime
3. Stops the daemon and keeps the previous binary and assets as rollback material
4. Activates the staged release and rehashes the config once
5. Restarts the daemon, checks sustained liveness, and runs `csm doctor`

### Signature check

Standalone deploy scripts require successful detached signature verification for current releases. They use the first verifier that is available, in this order:

1. OpenSSL 3.0 or later.
2. The installed CSM binary's `csm verify-release`.
3. `python3-cryptography`.

This keeps upgrades working on EL8 and CloudLinux 8, which have OpenSSL 1.1.1. It also covers the first upgrade to a build that provides `csm verify-release`.

When no verifier is present the upgrade stops. Disabling `CSM_REQUIRE_SIGNATURES` does not enable unsigned current upgrades. Set `CSM_VERIFIER_BINARY` to select a specific CSM binary. See [Release signing](release-signing.md) for the historical-release exception.

### Health gate

The health gate is step 5 above. It waits 20 seconds by default. Set `CSM_UPGRADE_HEALTH_SETTLE` to an integer from 1 to 3600 seconds for a longer or shorter observation window. Invalid values fail the gate.

Doctor warnings do not trigger rollback. Failed checks do.

### Automatic rollback

If activation, rehash, startup, or the health gate fails, the helper does this:

1. Stops the new daemon.
2. Restores the previous binary and assets.
3. Re-records the restored binary hash.
4. Starts the previous version.

It exits nonzero and reports where it retained recovery material. If recovery itself fails, it reports an incomplete rollback that needs operator attention.

## Optional nightly upgrades

Packages ship a disabled sample at `/opt/csm/configs/cron/csm-auto-upgrade`. It runs only after an operator installs it into `/etc/cron.d/`:

```bash
csm version && /opt/csm/deploy.sh check
sudo install -m 0644 /opt/csm/configs/cron/csm-auto-upgrade /etc/cron.d/csm-auto-upgrade
```

Confirm the host runs a published release first. The checksum check reports any different build as an available update. The downgrade guard rejects a lower version, but the published release can still replace a development build that has the same version.

### What the job does

The job invokes the standalone deploy helper every night between 03:30 and 04:30, with a random delay and a nonblocking lock.

The job updates runtime files directly. It does not update APT/DNF's installed package version. Hosts that need package-manager ownership and version tracking should use their package upgrade automation instead.

Staggering spreads upgrades over an hour but does not stop a bad release from reaching the fleet.

### Output and failure mail

Output goes to `/var/log/csm/auto-upgrade.log`. Failures also produce cron mail to root, so configure and test root's mail alias before enabling the job.

This notification does not depend on CSM's alert channels or on successful daemon recovery. Successful runs and an already-held lock produce no mail.

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

The package postinstall creates the FHS directories with the right ownership.

### Main config

What happens depends on the two config paths:

| Case | Result |
|------|--------|
| `/opt/csm/csm.yaml` is a real file, and `/etc/csm/csm.yaml` is absent or still the shipped placeholder | The package copies the legacy config into `/etc/csm/csm.yaml` and then replaces the old path with a symlink. |
| Both paths are real files with different operator content | CSM refuses the implicit default path until you move one aside or pass `--config <path>`. |
| Both paths are real files that differ only in the `integrity` hashes | CSM treats them as the same configuration. The daemon starts from `/etc/csm/csm.yaml`, and the next `csm rehash` replaces the legacy copy with the symlink. |

The `integrity` hashes are the ones CSM writes itself: `binary_hash`, `config_hash` and `confd_hash`.

### State directory

On first start the daemon copies a non-empty legacy `/opt/csm/state/` into the new state directory. It does so only when the new directory is empty, so a partial migration cannot corrupt it. The legacy directory is left in place. Remove it after you have verified the new install.

### Manual binary swap

Operators who upgrade by manual binary swap, without re-running the package postinstall, keep the legacy state path if `state_path: /opt/csm/state` is pinned in the existing `csm.yaml`. To move state to the FHS layout, do one of these:

- Reinstall the package.
- Create the directories by hand and remove the `state_path:` override.

## systemd `Type=notify` drop-in

The packaged unit file is `Type=notify` with `WatchdogSec=300`. The daemon signals `READY=1` after watchers attach and pings `WATCHDOG=1` on schedule. As a result `systemctl is-active` reflects truth and the watchdog kills a hung daemon.

Older units shipped `Type=simple`. The watchdog still works with them, because the daemon pings regardless of unit type. But `systemctl status` only sees the process, not "watchers attached." If you need the `Type=notify` behavior on an older unit, drop in:

```ini
# /etc/systemd/system/csm.service.d/notify.conf
[Service]
Type=notify
NotifyAccess=main
```

Then `systemctl daemon-reload && systemctl restart csm`. Verify with `systemctl show csm -p Type -p StatusText`.

## Auto-response dry-run safety default

`auto_response.dry_run` defaults to `true` when the key is absent. Automatic IP blocks are not applied.

If your `auto_response:` block sets `enabled: true` and `block_ips: true` but does **not** set `dry_run`, **add `dry_run: false` explicitly** before relying on auto-block. Read the live settings with `csm status --json | jq '.automation | {auto_response_dry_run, dry_run_blocks}'`. The top-level dry-run flag in the example below returns `null`. The count shows retained examples. Firewall history can also include manual blocks.

```bash
csm status --json | jq '.auto_response_dry_run, .dry_run_blocks'
csm firewall status            # check that "Recently Blocked" picks up new entries after the restart
```

With the firewall on and outside observe mode, `dry_run_blocks` counts the forecast examples CSM has retained. Older examples stay in the count until CSM prunes them. It is not the number of blocks that would still be active, and it is not a count of all attempted blocks.

Manual firewall blocks bypass dry run and still respect target protections.

## Admission applies automatic IP blocks

Admission is the part of CSM that decides whether an automatic IP block goes ahead, within an hourly ceiling and the free slots of the temporary set. [Auto-Response](auto-response.md) describes it. The legacy path is the older blocking code.

Version 4.14.0 only previews admission. Later releases apply automatic IP blocks through admission on a host that meets all of these:

- `auto_response.dry_run: false` is set.
- The firewall is on.
- The host is outside observe mode.

A host that already runs with `dry_run: false` does so from the first start of the new build.

### Checking the comparison before admission blocks

1. Set `dry_run: true` before the upgrade.
2. Compare a dry-run window as described in [finding streams](finding-streams.md#comparing-the-admission-preview).
3. Set `dry_run: false` once it passes.

### What changes after the upgrade

Legacy blocks applied before the upgrade stay until they expire. When admission wants a longer block for an address such a block already holds, the work waits for that block to end. For Critical work the wait raises a capacity notice with reason `pending_recovery`. The legacy block keeps the address blocked meanwhile.

The automatic block counter also counts the challenge, central and incident blocks admission applies, so block rates on dashboards can rise after the upgrade.

### Stopping admission blocks without a rollback

To stop admission applying blocks without changing the binary, set `auto_response.dry_run: true` and run `systemctl reload csm`. Dry run stops every automatic IP block, legacy ones included. Blocks already applied stay until they expire.

To return automatic blocking to the legacy path, roll back the binary instead.

### Before you upgrade: keep rollback material

The supported rollback target is the pre-flip 4.14.0 release. Older builds cannot safely read all admission records, and some also reject newer config keys. Removing config keys does not make those versions safe rollback targets.

Before upgrading:

- Retain a verified 4.14.0 package or release artifact and its matching assets.
- Retain the new artifact too, for recovery. The upgrade helper deletes its previous-binary copy after a successful upgrade.
- Resolve the active config and state locations, including drop-ins, and keep a restricted backup.

Keep the database and firewall state, including action identifiers and absolute expiries. Do not restore an older state snapshot to bypass a format check. [Admission state format and older builds](#admission-state-format-and-older-builds) lists the format rules.

### Rolling back to 4.14.0

For a rollback:

1. Set `auto_response.dry_run: true` in the effective configuration, reload, and confirm `csm status --json` reports `automation.auto_response_dry_run` as true. A drop-in may override the main config.
2. Confirm admission has stopped executing (`admission.owner.executing` is false) before proceeding. A failed reload is not a successful stop.
3. Note the installed version, the `csm doctor` result and the current timed blocks. Then stop `csm.service` and confirm it is inactive. Keep a consistent backup of the stopped database and firewall state.
4. Install the retained 4.14.0 package with the package manager, allowing the downgrade. The standalone helper installs only the latest release: on a standalone host, put the retained 4.14.0 binary and its assets in place and run `csm rehash` before starting. Do not substitute a locally compiled binary.
5. Start the service if the installer did not. Verify the running version, sustained service health and `csm doctor`, and compare remaining timed blocks and expiries with the saved inventory. Keep dry run enabled until these checks pass.
6. To resume legacy automatic blocking, set `auto_response.dry_run: false`, reload and verify the effective status. Leaving it true continues to suppress automatic blocking.

With dry run off on 4.14.0, the legacy path applies automatic blocks. Existing blocks retain their expiry. This procedure does not flush them or promise to restore already expired blocks.

### If the rollback fails

If installation or health checks fail:

- Keep dry run enabled.
- Restore the retained verified new release and its matching assets through the same workflow. Rehash if required, start, and repeat the health and block checks.
- Keep current state in place. Recover a damaged state backup only through the documented backup/restore procedure.
- Do not re-enable automatic blocks on a failed health check.

### Upgrading again after a rollback

Admission starts live once per ledger. The ledger is admission's own state in the state database. Upgrading again after a rollback does not repeat that start:

- Blocks the legacy path applied in the meantime stay until they expire.
- The legacy path's hour is not carried over into admission's hourly ceiling.

To compare a dry-run window again before admission blocks, keep `auto_response.dry_run: true` through the upgrade.

## Troubleshooting

### "store: opening bbolt: timeout"

Most operator commands that need live state route through the control socket at `/var/run/csm/control.sock`. This error should only appear in two cases:

- A command intentionally opens the bbolt file directly, such as `csm store compact`, `csm store import`, `csm store reset-bot-verify` or `csm db-clean --drop-object`.
- A second daemon starts while one daemon already owns the database.

Fix: stop the daemon before direct-store maintenance commands, then retry:
```bash
systemctl stop csm
csm store compact
systemctl start csm
```

If `systemctl` says CSM is stopped but bbolt still times out, find the process holding `/var/lib/csm/state/csm.db` and stop that process after review. Do not delete `csm.lock`. It is only the daemon instance guard and does not release bbolt's file lock.

### "csm: daemon not running"

CLI commands that talk to the daemon exit 2 with this message when the control socket is missing. Start the daemon with `systemctl start csm`.

| Commands | Need the daemon |
|----------|-----------------|
| `csm run*`, `csm check*`, `csm baseline`, `csm status`, `csm firewall ...`, `csm store export`, `csm export --since`, `csm phprelay ...` | Yes |
| `csm install`, `csm validate`, `csm config schema`, `csm verify`, `csm rehash` | No. These bootstrap commands run before the daemon exists. |

### Never delete `csm.db`

`csm.db` contains all historical findings, firewall state, email forwarder baselines, and per-account data. If you delete it, the web UI shows empty data until the next full scan cycle, which is up to 60 minutes for deep scan findings.

Restore from backup when possible. For an intentional reset, run `csm baseline --confirm` rather than removing the database by hand.

### Config changes require rehash

| Change | What to do |
|--------|------------|
| A restart-required field in `csm.yaml` or any conf.d drop-in | Run `csm rehash` once, validate, then restart. |
| A hot-reload-safe change | Run `systemctl reload csm`. The daemon validates the accepted config and re-records its hash itself. |

A restart that fails with `conf.d hash mismatch` means a drop-in changed since the hashes were last recorded. Rehash if the change was intentional. If an integration rewrites a fragment on its own, list that fragment under `confd.integrity_exempt` so it stops needing a rehash. `csm doctor` reports the mismatch while the daemon is still up.

## Details

This section is reference material for rollbacks across admission state formats.

### Admission state format and older builds

Admission's state has a schema number. Some events raise it, and a build that does not know the new number cannot use that state. The rules below use the names of admission's own records, which [Development](development.md) describes.

| Event that raises the format | Schema | Effect on older builds |
|------------------------------|--------|------------------------|
| The first disabled queued response | 10 | Binaries that read only schema 9 cannot open it. They keep blocking with the legacy budget. |
| The first positive elapsed episode end that CSM records, including on hosts that only preview or forecast | 13 | Older binaries cannot open it and keep blocking with the legacy budget. |
| The first verified block, which is written only on hosts where admission executes | 15 | Older builds refuse this ledger. |

Never delete the state database or replace it with an older copy to get past the format check. Stop the daemon before replacing the binary, and keep the database when changing binaries.

### Which builds you can roll back to

| State of the host | Roll back only to a build that |
|-------------------|--------------------------------|
| Schema 13 was reached | Supports both schema 13 and elapsed episode records. |
| Schema 15 was reached | Reads schema 15, understands the recorded verified generation, and retains and cleans up these rows. |
| Live re-admissions happened | Also keeps the episode's original verified end and caps queued returns, the blocks waiting to be applied again, at that end. A build that only reads the format can give an old queued return a full new lifetime. |

### What preview and live admission record

While admission only previews and forecasts, it creates no genuine charge, attempt or unknown hold beyond the state legacy blocking keeps. Preview accounting is not enforcement state. The schema 10 behavior above is not a downgrade guard for a ledger that has executed real actions.

A live admission ledger records each episode's latest verified block. It retains a verified episode's boundary even after an unattempted return is forgotten.
