# CLI Commands

Packages and the standalone installer expose `/usr/sbin/csm`, which points to `/opt/csm/csm`. Commands that talk to the control socket need the daemon to be running. Direct-store maintenance commands say explicitly when the daemon must be stopped.

## Global flags

| Flag | Description |
|---------|-------------|
| `--config <path>` | Override the main config path. Default: `/etc/csm/csm.yaml`, with fallback to `/opt/csm/csm.yaml` on legacy installs. |
| `--config-dir <path>` | Override the conf.d directory. Default: `/etc/csm/conf.d`. Wins over `CSM_CONFIG_DIR` when both are set. |

A conf.d directory override, from `--config-dir` or `CSM_CONFIG_DIR`, must be absolute, trusted, and not group- or world-writable. Loaded fragments must meet the same write-safety check.

`csm rehash` and `csm capabilities` reject missing option values before recording hashes or printing output. `csm capabilities` accepts but does not read config paths.

## Daemon

| Command | Description |
|---------|-------------|
| `csm daemon` | Run as persistent daemon (fanotify + inotify + PAM + periodic checks). |

### Systemd notifications

- The daemon signals systemd `READY=1` after watchers attach, and pings `WATCHDOG=1` on the configured interval.
- It reads the systemd notification variables once at startup and removes them from the environment, so no command the daemon runs inherits them.
- Notification writes time out if systemd stops reading its socket, so they cannot block the daemon indefinitely.

### ModSecurity rule actions

The daemon checks ModSecurity rule actions every five minutes using file contents, including linked rule files.

- Unchanged rule trees skip parsing.
- If a check finds no rules, or cannot read every rule file, the daemon tries again at the next check.
- If the rule directories it selected stop yielding rules, the daemon detects the web server platform again.
- A temporarily empty tree keeps the last loaded actions until a replacement is available.

## Checks

| Command | Description |
|---------|-------------|
| `csm run` | Run all checks now via the daemon, send alerts |
| `csm run-critical` | Critical checks now via the daemon (the daemon also schedules critical checks internally every 10 min) |
| `csm run-deep` | Deep checks now via the daemon (the daemon also schedules deep checks internally every 60 min) |
| `csm check` | Run all checks via the daemon, print findings to stdout, no alerts / auto-response |
| `csm check-critical` | Test critical checks only (dry-run via daemon) |
| `csm check-deep` | Test deep checks only (dry-run via daemon) |
| `csm scan <user> [--alert]` | Scan a single cPanel account (capped quick scan). `--alert` sends alerts for the findings. |
| `csm scan <user> --full [--wait] [--json] [--respect-ignores] [--quarantine]` | Uncapped deep scan of one account, routed through the daemon. Report-only by default. See [Full scans](#full-scans). |
| `csm scan --all --full [--wait] [--json] [--respect-ignores]` | Server-wide uncapped full scan across every account. Quarantine per account after review (`--quarantine` is rejected with `--all`). |
| `csm scan --status [id] [--json]` | List full-scan jobs, or show one job by id. |
| `csm scan --report <id> [--json]` | Print the stored report for a completed full-scan job. Exits with status 3 when that scan did not cover everything. |
| `csm scan --cancel <id> [--json]` | Cancel a running full-scan job. |

### How a scan finds the account home

An account whose home is on an additional home partition is found through the cPanel account list and its passwd home.

Passwd home fallback accepts an account-named directory directly under a sibling home volume, such as `/home2`. It rejects symlinked volumes and homes. Arbitrary passwd locations outside this boundary are not used for account scans.

### Full scans

A full scan (`--full`) bypasses the per-account file cap. It also runs the YARA rules over the account's document roots, one file at a time through the YARA worker. The default account scan has no YARA pass.

| Flag | Effect |
|------|--------|
| `--wait` | Polls to completion and prints the report. Exits with status 3 when the scan stopped early, was canceled or failed. |
| `--respect-ignores` | Honors `ignore_paths`. |
| `--quarantine` | Acts on critical file findings the way the scheduled auto-response does. Without it the scan is report-only. |

With `--quarantine`:

- WordPress core, plugin and theme files are cleaned in place, unless cleaning would leave them empty or their release does not ship them.
- Directories, symlinks and lower-severity findings are left for review.

The YARA pass follows these rules:

- Files over `full_scan_max_file_mb` are reported as not scanned.
- Image files are scanned after everything else, so a scan that runs out of time has read the code first.
- It does not follow tenant symlinks.
- It reports unreadable or changed files and directories as coverage gaps.
- It keeps confirmed matches if a later read or worker call times out.

Large worker requests use a private temporary snapshot in the daemon state directory, bounded by `full_scan_max_file_mb`. The snapshot is removed after the request. Failure to create or scan that snapshot is reported as incomplete coverage.

### Exit status 3

Exit status 3 means the scan did not cover everything:

- a check timed out or failed;
- a file was skipped as oversize or unreadable;
- the account was not found;
- not every finding was stored.

## Management

| Command | Description |
|---------|-------------|
| `csm install` | Deploy config, systemd, auditd rules, logrotate, WHM plugin |
| `csm uninstall [--purge]` | Remove the executable and CSM-owned integrations. Config and data are kept unless you add `--purge`. See [Uninstall](#uninstall). |
| `csm baseline` | Full server scan via the daemon, records current state for change tracking. Required on first install. See [Baseline](#baseline). |
| `csm rehash` | Re-record the binary, `csm.yaml` and conf.d hashes without scanning. See [Rehash](#rehash). |
| `csm status` | Show current state, last run, active findings, and automation rollout state. Add `--json` for the full health snapshot (watchers, severity counts, store health, blocklist size, capabilities, version, hashes, automation). |
| `csm verify-release <key.pem> <file.sig> <file>` | Verify a release artifact's Ed25519 signature without OpenSSL; the supported verification path on EL8 and CloudLinux 8. |
| `csm systemd-roots` | Print a validated systemd drop-in granting write access to configured account trees; see [custom account roots](custom-account-roots.md). |
| `csm privileges [--json] [--markdown]` | Print every operation that needs privilege beyond reading CSM's own files, with what it writes and the config key that stops it. See [Privileges](#privileges). |
| `csm action show <id>` | Print, as JSON, what the admission ledger recorded for one automatic response. Asks the running daemon. See [Action show](#action-show). |
| `csm actions [--since <when>] [--op <id>] [--limit N] [--json]` | Print what CSM did to this host: quarantines, cleans, process kills and firewall changes, with the digest before and after a file change. Reads the log directly, so it answers after a crash. See [action log](action-log.md). |
| `csm selftest [--json]` | Scan a bundle of samples with known verdicts and report what the installed rules catch, including the gaps the bundle records. Reads no account data. See [self-test](self-test.md). |
| `csm doctor` | Sanity check of config, integrity, daemon, watchers and store. Add `--json` for machine-readable output. See [Doctor](#doctor). |
| `csm validate` | Validate config (`--deep` for connectivity probes) |
| `csm config show [--no-redact] [--json]` | Display the redacted config even when callback secrets are set only in the service environment. With `--no-redact`, a missing required callback secret stops the command before it prints the config. Use `--json` for JSON output. |
| `csm config schema` | Print a JSON Schema reflected from the `Config` struct. Use for CI validation of conf.d drop-ins or panel-side editor schemas. |
| `csm config apply-immutability` | Reapply `integrity.immutable` to `/opt/csm/csm`. Package transaction hooks use this after upgrades. See [Apply immutability](#apply-immutability). |
| `csm verify` | Verify binary and config integrity |
| `csm version` | Version and build info |
| `csm capabilities` | Print this build's feature tokens, one per line; `--json` prints a JSON array. See [Capabilities](#capabilities). |
| `csm incidents ...` | List, show, and update correlated security incidents (`list`, `show <id>`, `status <id> <state>`, `bulk-status`). See [Incidents](incidents.md). |
| `csm forensic-snapshot <account> --out <archive.tar.gz>` | Evidence archive for incident handoff (triggers, admins, sessions, file mtimes). |
| `csm support-bundle <path> [--journal-lines N]` | Write a private tar+zstd archive with the recent service log (default 1000 lines), redacted configuration, system versions, integrity results and store diagnostics. See [Support bundles](#support-bundles). |
| `csm webserver-integration <install\|upgrade\|status\|validate\|remove>` | Install, upgrade, or remove the challenge reverse-proxy snippets for the detected web server. |
| `csm pam <install\|uninstall\|status>` | Install or remove the `pam_csm.so` PAM hook (`csm pam --help`). |
| `csm report enroll` | Generate an abuse-reporting node key pair. |

### Uninstall

`csm uninstall` removes the executable and the CSM-owned service, audit, logrotate, webserver and ModSecurity integrations.

| Data | Default | With `--purge` |
|------|---------|----------------|
| Config, drop-ins, state, logs, signature rules and quarantine data | Preserved | Removed, with all other CSM-owned data |
| Operator ModSecurity rules | Never removed | Never removed |

Uninstall is intentionally non-destructive unless `--purge` is supplied.

### Baseline

`csm baseline` runs a full server scan through the daemon and records the current state for change tracking. It is required on first install, and the daemon must be running.

- It takes 5-10 min on large servers.
- Dangerous privileged accounts or WHM root tokens can still be reported on the first scan.
- Add `--confirm` when existing history would be cleared.

### Rehash

`csm rehash` re-records the binary, `csm.yaml` and conf.d hashes without scanning. It also applies `integrity.immutable` to the installed binary.

Run it once after you edit restart-required config, change a drop-in by hand, or replace the binary. A stale hash makes the next restart refuse to start.

`csm rehash --fragment <file>` re-records hashes only when the named conf.d files are the only change. See [conf.d drop-ins](configuration.md#confd-drop-ins) for its exit codes.

Unknown arguments are refused rather than ignored.

### Privileges

`csm privileges` reads nothing from the host, so it answers "what would this do to my server" before installing. See [capability matrix](capability-matrix.md).

### Action show

`csm action show <id>` prints what the admission ledger recorded for one automatic response. The admission ledger is CSM's record of its automatic responses. The output has:

- the candidate with its state, reason and outcome;
- each attempt;
- for a response refused because a block already enforced it, that block.

`<id>` is a candidate ID or the `action_id` of an admission record. See [action log](action-log.md).

### Apply immutability

`csm config apply-immutability` reapplies `integrity.immutable` to `/opt/csm/csm`.

| Result | Exit |
|--------|------|
| Unsupported filesystem or missing tooling | A warning and a successful exit |
| Permission error or another unexpected error | Failure |

### Capabilities

`csm capabilities` needs no running daemon and no config. An orchestrator can therefore check a token before it writes a key that depends on it.

Tokens for live BPF monitors appear only in the daemon's `GET /api/v1/capabilities`.

### Doctor

`csm doctor` is a sanity check of config, integrity, the daemon, the watchers and the store. It includes service write access for custom account roots. Add `--json` for machine-readable output.

| Check | What it covers |
|-------|----------------|
| Config | Includes the firewall lockout warnings for inbound and outbound policy. |
| Integrity | Reports a binary, `csm.yaml` or conf.d hash mismatch before the next restart refuses to start, with the remedy. |
| Watchers | Includes the YARA-X scanning worker, which fails while it is down or keeps crashing. |

The sections below describe the other lines doctor prints.

#### PHP Shield on CloudLinux

On CloudLinux with PHP Shield enabled, doctor reports whether the Shield event mount has been applied to the cages.

- It names up to five missing cages and gives per-account remount commands.
- Unresolved accounts appear as `uid:N`. Resolve their account names before remounting.
- For more than five missing cages, it also offers a remount of all cages during a maintenance window.

#### `smtp auth logging`

On Postfix hosts with Dovecot, this line warns when:

- Dovecot does not log rejected logins, which SMTP brute-force detection needs;
- Dovecot logs their passwords;
- its settings cannot be read.

#### `correlation attribution`

This line looks at findings in the active set that have no hosting owner.

| Status | Meaning |
|--------|---------|
| WARN | Names the checks whose findings sit in the active set without a hosting owner. |
| OK | Confirms every eligible finding carries one. |

Either way it gives the cumulative count since start.

#### `web client addresses`

This line says what the web server configuration does with client addresses.

| Web server configuration | Status |
|--------------------------|--------|
| Sets no client address rewriting | OK |
| Replaces the logged client address | OK, naming the setting and its file. Web findings then get no automatic response from admission. |
| Cannot be read completely | WARN |

Doctor applies the loaded `web_server:` settings before reading the files. The configuration root selects Apache or nginx, including cPanel LiteSpeed's Apache tree. LiteSpeed XML stays at its standard location.

#### `login sources`

This line names the sources selected for SSH, mail and FTP. A source is one of:

- service journal entries;
- Stalwart's own log;
- untrusted syslog files that only alert (WARN).

Mail selection follows `mail_logs.source`, including journal fallback when an automatic file source is missing. Stalwart uses its own log regardless of that setting.

Missing mail files without a fallback, missing journal units and builds without journal support produce warnings.

Selection does not prove a reader is running. Watcher health reports source availability.

#### Stalwart lines

On Stalwart hosts, doctor prints two kinds of lines:

- The `stalwart API key` line says whether Stalwart accepts CSM's API key from `stalwart.api_key_file`.
- The `stalwart` setup lines check Stalwart's settings, read-only, through that key.

Without a working key, doctor uses an admin login from `STALWART_USER` and `STALWART_PASSWORD` when both are set. Otherwise it does not check the settings.

The key is sent only to an API address on this host whose port belongs to root or Stalwart's service user. For a remote address doctor uses the admin login only.

#### `csm doctor challenge`

`csm doctor challenge` checks challenge public URL, TLS, port gate, webserver snippets, configtest, and the live `/challenge/gate` endpoint.

#### `deploy scripts verify releases`

This check looks for shell scripts with `deploy` in their names in `/opt/csm`, `/root`, `/usr/local/sbin` and `/usr/local/bin`.

| Status | What it lists |
|--------|---------------|
| OK | Copies that match the deploy scripts shipped with this version of CSM. |
| FAIL | CSM scripts with a known legacy signature-skip warning. |
| WARN | Other recognizable CSM copies, including locally edited scripts, and paths doctor could not inspect. |

A failure takes precedence over a warning. Compare nonmatching copies with the release scripts before deploying.

#### Protection queue health

`csm doctor` also lists [protection queue health](api.md#protection-queue-health): waiting and running work, losses and lag.

- A sustained backlog or drop rate fails the named queue check and includes recovery guidance.
- Queues whose work is best effort warn instead of failing, so they never change the exit status.
- While the firewall is disabled, queued automatic blocks pass the check. The check says the blocks are not applied and whether dry run is on.

The same evidence appears in `csm status --json` and the HTTP status response.

#### `backend: <feature>`

Each started live monitor also gets a `backend: <feature>` check naming the backend it runs on, such as `backend: placement`.

A monitor on `none` passes when its `detection.<feature>_backend` is `none`. Otherwise it warns, with a pointer to the startup log.

### Support bundles

Support bundles use a new filename and mode 0600. Use a directory owned by root or the collecting account, with the same directory protections as `csm store export`.

What goes in:

- The store part needs a running daemon with the `support_bundle.v1` capability. It omits key files and symbolic links.
- CSM checks the decompressed contents for configured credentials and private keys, and verifies the digest of the bytes it includes.

Run the collector with the service's configured secret environment. The running daemon compares its redaction settings with the collector's before releasing diagnostics.

| Case | Result |
|------|--------|
| The redaction settings differ, or a referenced credential is unavailable | The bundle omits the journal and store. |
| The daemon is offline | Journal redaction uses the supplied configuration. |
| A journal request above 16 MiB, a store containing detected credentials, or an unavailable part | The bundle gets a `.err` entry with the reason. |

Review logs and store data for older credentials, embedded backups, account names and addresses before sharing.

## Backup & restore

| Command | Description |
|---------|-------------|
| `csm backup <path>` | Bundle `csm.yaml`, `/etc/csm/conf.d/`, the state directory and the antispam learning directory into a tar.gz at `<path>`. The daemon must be stopped. |
| `csm restore <archive> [--force]` | Validate and stage the complete archive, then atomically replace the live `csm.yaml`, `conf.d`, state directory and antispam learning directory. Stop the daemon first. |

`csm store export` / `csm store import` (below) is the lower-level alternative: tar+zstd, sha256-verified, finer-grained `--only=` flags. `csm backup`/`restore` is the convenience wrapper most operators want.

### What backup does

- It omits runtime lock files, in-progress export staging, and unconfirmed firewall rollback artifacts.
- It verifies both the control socket and the state lock before reading data.

### What restore does

- It refuses a running or starting daemon.
- It stages all data beside its destination before replacement, so validation failures leave the live installation unchanged.
- It rolls back failed replacements and removes stale state entries.
- It moves the antispam learning directory it replaces aside instead of deleting it. Restored learning state holds new reports until the daemon has run with learning disabled outside observe mode. See [Antispam](antispam.md#teaching-and-correcting-learning).

Backup and restore use the state lock to exclude daemon access.

### Archive format

Restore accepts the format produced by `csm backup`: one tar archive in one gzip member. The archive must have no data or padding after the tar end markers, and no trailing compressed bytes or additional members.

Restore validates the gzip checksum and length before replacing any destination, and rejects corrupt or truncated archives.

### Size limit

Both commands stream file contents. They limit the total uncompressed tar archive to 16 GiB by default, including headers, manifest and padding. There is no separate limit on a state file.

- Use `--max-bytes <positive byte count>` on both commands to raise or lower the budget.
- Restore also accepts older large backups when they fit the selected budget.
- An over-limit backup fails without replacing an existing archive.
- Restore keeps its manifest read limited to 64 KiB.

### Disk space

Backup checks space before copying the state database snapshot. Restore checks before each staged file and each replacement copy, including copies onto a different destination filesystem. These checks leave 64 MiB free beyond the file being copied.

Allow space for the old installation, the full extracted archive, and a second copy of the restored files during replacement.

Space checks cannot reserve storage against other writers. Write failures still abort staging before live replacement.

If a limit or space check fails, retain the original archive, provision enough storage, and retry with the same or a higher explicit budget.

### Login standing

Login standing is left out of backups and exports, and removed during a restore or a full store import. Addresses earn it again from new logins.

### Archives with an older admission ledger

Once this host's admission ledger has started live, restore and `csm store import` refuse an archive whose ledger is behind it. An archive's ledger is behind when it never started live, or when its clock is behind. Restoring it would spend an hour's block budget twice and replay the live start from older blocks.

| Case | Result |
|------|--------|
| `--only=baseline`, and the archive carries the firewall state | Refused too, because it puts that file beside the newer ledger. |
| `--only=firewall` | Not refused. |
| The host ledger never started live, or the host has none | Not subject to this comparison. |
| This build cannot read the host ledger, including a truncated database | Not refused, so a restore can repair it. |

Pass `--force` to either command to bypass this comparison.

### Damaged databases

Backup, export, import and restore check each database snapshot before reading or changing it. They refuse a damaged one, including one with leaked pages. They make consistent backups, not salvage copies of damaged databases.

Two operations also check the live database:

- `csm store import --only=firewall` checks the live database.
- When an archive contains antispam learning and omits state, restore checks the staged copy of the live database before replacing any files.

Both refuse a damaged database or a broken database symlink, and accept leaked pages in the live database.

### Store import format checks

- `csm store import` rejects archives that place `csm.db` among state files. The database belongs only in `bbolt.snapshot`.
- A baseline import carrying `firewall/state.json` also verifies the snapshot's checksum when the manifest provides one.
- `--force` does not bypass either format or checksum validation.
- Baseline imports without firewall state still ignore the unused snapshot.

## Hardening

Operator-driven mitigations applied to the host. Run `csm harden` with no arguments to print the subcommands available on the current host. The audit detects the kernel build, the panel and existing mitigations, and only offers what is relevant. Background, full list, and live-detection details: [CVE Mitigations](cve-mitigations.md).

| Command | Description |
|---------|-------------|
| `csm harden` | Print the hardening menu for this host. |
| `csm harden --copy-fail` | Apply the CVE-2026-31431 (Copy Fail) modprobe mitigation: blacklist `algif_aead` + `af_alg`, unload them. Refuses on built-in-AF_ALG kernels. |
| `csm harden --copy-fail-seccomp` | Apply the CVE-2026-31431 seccomp mitigation: write systemd `RestrictAddressFamilies=~AF_ALG` drop-ins for LiteSpeed, Apache/Nginx, every PHP-FPM pool, cron, and mail units. The right path on built-in-AF_ALG kernels (typical cPanel/CloudLinux 8). |

### Applying fixes from the Web UI

The web UI's Server Hardening page can also apply fixes one section at a time. A failing check that has a safe, mechanical fix shows an **Auto-fix** checkbox.

Five fixes can disrupt a working host. They start unticked and say what they can break:

- strict reverse-path filtering;
- the 200 messages an hour cap;
- blocking mail sent as nobody;
- strict cookie IP validation;
- `MaxAuthTries 4`.

Saved audits also show these cautions without needing a new audit.

**Apply selected fixes** changes only the checked items, then re-runs the audit. The page waits for the worker to finish.

- Only one hardening worker can run at a time, including across daemon restarts.
- The worker uses the daemon's main configuration and drop-in directory.
- Applying fixes requires root and `systemd-run`.

### Applying fixes through the API

For API callers and the root worker, an omitted or empty `names` list applies the section's uncautioned fixes. Cautioned fixes return `skipped` with an explanation. Include their check names explicitly in `names` to apply them. The request and response formats are unchanged.

### What each fix changes

- SSH `MaxAuthTries 4`, `X11Forwarding no` and `UseDNS no` go into a CSM block at the top of `sshd_config`. The file is checked with `sshd -t` before sshd reloads, and restored if the check fails. The previous file is kept as `sshd_config.csm-bak`.
- Kernel settings are set with `sysctl -w` and saved to `/etc/sysctl.d/99-zz-csm-hardening.conf`. A missing drop-in directory stops the fix before kernel settings change.
- `/tmp` and `/var/tmp` become `1777` owned by root. `/etc/shadow` becomes `0600`, or `0640` when the system shadow group owns it.
- WHM tweak settings are changed through `whmapi1 set_tweaksetting`, with 200 for max emails per hour. Compilers are restricted to root, and cPanel updates are set to daily.
- PHP `expose_php`, `enable_dl`, upload progress and fatal error backtraces are turned off in `zz-csm-hardening.ini` in each build's scan directory, and in every SAPI's `conf.d` on Debian and Ubuntu.

After a PHP fix, PHP-FPM restarts, Apache reloads when mod_php was changed, and LiteSpeed receives a fresh restart request on each apply.

The PHP fix has these edge cases:

- If a Debian or Ubuntu web SAPI cannot be updated, the CLI setting stays pending for retry.
- Linked or unreadable SAPI directories require manual changes.

SSH port, password and root login settings, `disable_functions`, `allow_url_fopen`, and the mail, web server and firewall checks stay manual.

### Undoing a fix

Fixes CSM applied show an **Undo** button. Undo puts back what the last apply of that one fix changed and leaves other fixes alone, including fixes that share its file. The audit then runs again, unless the undo was refused. Like Apply, Undo runs in the root worker and needs root and `systemd-run`.

What undo restores, by fix:

- SSH: the setting leaves CSM's block, or gets back the value the block had, and an empty block is removed. Every line CSM commented out for that setting is enabled again, including lines commented out before the last apply of this fix. As on apply, sshd checks the file before it reloads, and the file before the change is kept as `sshd_config.csm-bak`.
- Kernel settings: the drop-in gets back the lines it had for that key, or loses the key, and `sysctl -w` sets the runtime value back. When the drop-in write failed on apply, only the runtime value is set back.
- `/tmp`, `/var/tmp` and `/etc/shadow` get back their owner and mode.
- WHM tweak settings are set back with `whmapi1 set_tweaksetting`. See [WHM tweaks that cannot be put back](#whm-tweaks-that-cannot-be-put-back).
- Compilers: if the apply changed the compiler's mode, undo puts back its owner and mode. If the apply ran `/scripts/compilers off`, undo runs `/scripts/compilers on`, which sets cPanel's own modes, not the earlier ones.
- cPanel updates: `/etc/cpupdate.conf` gets back its earlier `UPDATES` lines, including any the apply commented out, in their earlier order. Undo refuses if identical comments cannot be distinguished after an edit. Every other line stays as it is now, so saving WHM Update Preferences after the apply does not block undo.
- PHP: each drop-in the apply wrote gets back the key's earlier line, or loses the key, and PHP reloads as on apply.

A CSM drop-in left with only its header is removed.

#### WHM tweaks that cannot be put back

cPanel has no call that clears a value, and cPanel's own checks can refuse an earlier value, such as 0 for max emails per hour. Two kinds of tweak therefore cannot be put back:

- a tweak that had no value or an empty one before the apply;
- a tweak whose earlier value cPanel refuses.

Undo then refuses, leaves the applied value, and asks you to set it back in WHM Tweak Settings.

- When the tweak had no value or an empty one, the apply result says so even on repeated applies. Once WHM shows no value again, the next undo clears the record.
- WHM cannot store a refused value such as 0, so that Undo keeps refusing until the next apply.

#### When undo refuses, fails or has nothing to do

| Case | What undo does |
|------|----------------|
| The setting does not hold what the apply set, because it was changed since | Refuses. A refused undo changes nothing and keeps the record, so the page keeps offering Undo until the next apply replaces the record. |
| The setting is already back to its state before the apply, for example after you reset a tweak that had no value in WHM Tweak Settings | Changes nothing, removes the record and reports the fix undone. |
| The undo fails | Puts back what it had changed and keeps the record, so it can be retried. If that also fails, the message says what is left to fix. |
| An sshd or PHP reload fails | Does not fail the undo. As on apply, the restored settings stay and the result says what to reload by hand. |

SSH counts as already restored only when its global lines are enabled in their earlier order and no line for that setting remains disabled by CSM.

#### Undo records

Applying a fix again keeps the state from before the first apply for each setting that still holds CSM's change. Undo therefore goes back to the state before CSM changed it.

If CSM cannot record the earlier state, the fix still applies, its result says "Undo is unavailable", and it shows no Undo button. Fixes applied by an older CSM have no record either.

The records live in `/var/lib/csm-hardening-undo`, which only root can read or write. `csm uninstall --purge` removes them.

- Each fix has at most one record. Its next apply replaces it, and a successful undo removes it.
- The root worker writes and removes the records.
- The daemon only lists their names to show the Undo button.
- An undo request carries only the fix name.

## Remediation

| Command | Description |
|---------|-------------|
| `csm clean <path> [--preview]` | Clean an infected PHP file, or remove malicious directives from an `.htaccess` under a detected or configured account root (backs up original). `--preview` prints the change as a unified diff and writes nothing; oversized or binary previews fail without writing. |
| `csm db-clean --option <account> <option_name> [--preview]` | Sanitize malicious WordPress option values (e.g. injected `siteurl` / `home`). `--preview` prints the cleaned value as a unified diff. Apply preserves concurrent edits and reports any retained backup. |
| `csm db-clean --revoke-user <account> <user_id> [--demote] [--preview]` | Revoke or demote a compromised WordPress admin and invalidate their sessions |
| `csm db-clean --delete-spam <account> [--preview]` | Delete published posts whose title or content matches a high-confidence spam keyword. See [Spam post deletion](#spam-post-deletion). |
| `csm db-clean --drop-object <account> <schema> <type> <name> [--preview]` | Drop a MySQL trigger / event / stored procedure / stored function, after saving its CREATE SQL. Daemon must be stopped. See [Dropping a database object](#dropping-a-database-object). |
| `csm virtual-patch [--apply]` | Re-scan web roots and preview reversible access-file deny rules as unified diffs. Requires root and manual or auto mode. See [Virtual patch](#virtual-patch). |
| `csm enable --php-shield` | Enable PHP runtime protection |
| `csm disable --php-shield` | Disable PHP runtime protection |

### Spam post deletion

`csm db-clean --delete-spam` confirms each match on a Unicode-aware word boundary, so a post is never removed for containing a keyword inside a longer word. Keywords that also occur in ordinary writing are reported by scans but never deleted.

### Dropping a database object

`csm db-clean --drop-object` captures the object's CREATE SQL into the `db_object_backups` bbolt bucket first.

- `<type>` must be `trigger`, `event`, `procedure`, or `function`.
- `<schema>` must match a database discovered for `<account>`.

### Virtual patch

- A preview that cannot be shown exits nonzero.
- A timed-out partial scan applies only findings already confirmed reachable, and exits nonzero.

### PHP Shield files

Installing or enabling PHP Shield creates `/opt/csm/shield.conf.php` only when it is missing, so your edits survive. Update its allowed IPs by hand after changing `infra_ips`. Disabling keeps the file. Uninstalling removes it.

A PHP pool with `open_basedir` must allow `/opt/csm/`, not just the shield script. Otherwise the shield ignores `/opt/csm/shield.conf.php` and uses its defaults.

A `.csm-shield-disable` file only works where `open_basedir` allows the account's home folder.

## State database

| Command | Description |
|---------|-------------|
| `csm store compact` | Reclaim unused space in the bbolt state file (atomic rename over the live DB). Requires the daemon to be stopped (`systemctl stop csm`) because bbolt holds an exclusive file lock while running. |
| `csm store compact --preview` | Snapshot into a temp file next to the live DB and print src/dst sizes without replacing anything. Use to estimate reclaim before scheduling a maintenance window. |
| `csm store export <path>` | Write a tar+zstd backup containing the bbolt store, the state directory, and the signature-rules cache. Daemon must be running. See [Store export](#store-export). |
| `csm store import <path>` | Restore from a backup archive. Daemon must be stopped. Default restores everything. See [Store import flags](#store-import-flags). |
| `csm store reset-bot-verify` | Drop cached bot PTR verification results and missing-PTR records so the next scan re-runs reverse DNS checks. Requires the daemon to be stopped because bbolt holds an exclusive file lock while running. |
| `csm export --since <when>` | Dump audit-log events for SIEM backfill. Daemon must be running. See [Audit export](#audit-export). |

### Store export

`csm store export` omits private in-progress staging files and unconfirmed firewall rollback artifacts. A sibling `<path>.sha256` companion file holds the archive hash for verification.

### Store import flags

| Flag | Effect |
|------|--------|
| `--only=baseline` | Restores only state JSON files (file hashes). |
| `--only=firewall` | Merges the firewall buckets into the existing bbolt in one transaction. |
| `--force-platform-mismatch` | Allows restoring an archive captured on a different OS / panel / web server. |
| `--force` | Allows an admission ledger behind this host's live one (see Backup & restore). |

With `--only=firewall`, a durable firewall journal and its snapshot in the archive replace the target's. The import refuses while either side has a durable firewall action unresolved or its audit undelivered.

### Audit export

`<when>` is RFC 3339 (`2026-04-01T00:00:00Z`) or a duration relative to now (`24h`, `7d`).

`csm export` prints one JSON event per line on stdout, in the same `v=1` schema the live audit_log sinks emit. Pipe to a file or directly into a log shipper.

## Updates

| Command | Description |
|---------|-------------|
| `csm update-rules` | Download latest signature rules |
| `csm update-geoip` | Update MaxMind GeoLite2 databases |
| `csm update-bot-ranges` | Refresh built-in AI-crawler IP ranges from vendor feeds |

## PHP-relay (mail abuse, cPanel only)

Operator controls for the email PHP-relay detector. They talk to the daemon's control socket, so the daemon must be running. See [Real-time detection](detection-realtime.md#php-relay-mail-abuse-cpanel-only) for what the detector fires on, and [Auto-response](auto-response.md#actions) for the freeze action.

| Command | Description |
|---------|-------------|
| `csm phprelay status` | Print the detector's current state as JSON. Use to confirm the watcher is wired on a fresh install. |
| `csm phprelay ignore-script <scriptKey> [--for-hours N] [--persist] [--reason ...]` | Suppress every path for a `host:/path` scriptKey. Default TTL 168h (7d). |
| `csm phprelay unignore <scriptKey> [--persist]` | Remove an active ignore. `--persist` also deletes the bbolt row. |
| `csm phprelay ignore-list` | List all active ignores as JSON: scriptKey, expiresAt, addedBy, reason. |
| `csm phprelay dry-run on\|off\|reset [--persist]` | Override the auto-freeze dry-run state at runtime. See [Dry-run override](#dry-run-override). |
| `csm phprelay thaw <msgID>` | Manually thaw a frozen Exim message. |

### Status output

`csm phprelay status` reports:

- enabled;
- platform;
- effective dry-run + source (runtime/bbolt/csm.yaml);
- Path 2b effective account limit;
- scripts/IPs/accounts tracked;
- msgID-index size;
- active ignores.

### Ignoring a script

`<scriptKey>` is the value the daemon prints in `email_php_relay_abuse` and `email_php_form_relay_script` findings, for example `shop.example.com:/wp-admin/admin-ajax.php`.

`--persist` writes to the bbolt `phprelay:ignore` bucket, so the suppression survives daemon restarts. Without it the entry is in-memory only.

### Dry-run override

| Value | Effect |
|-------|--------|
| `on` | Freeze findings are emitted but no `exim -Mf` runs. |
| `off` | Live freezes. |
| `reset` | Clears the runtime override and falls back to bbolt or `csm.yaml`. |

Precedence: runtime > bbolt > yaml.

`--persist` writes the `on`/`off` choice to the bbolt `phprelay:settings` bucket, so it survives restarts. On `reset --persist` the bbolt row is also deleted.

### Thawing a message

`csm phprelay thaw` wraps `exim -Mt` with msgID validation: it rejects anything that isn't `[A-Za-z0-9-]{16,32}`. It writes a `thaw` entry to the auto-freeze JSONL audit at `/var/log/csm/php_relay_audit.jsonl`.

## Antispam learning (cPanel only)

Teaches or corrects [learning from Spam folders](antispam.md#teaching-and-correcting-learning). Runs as root against the running daemon while learning is enabled. Observe mode refuses it.

| Command | Description |
|---------|-------------|
| `csm antispam learn --spam <file>...` | Learn each saved message as spam; every cluster it matches gains one operator mark. |
| `csm antispam learn --forget <file>...` | Remove the learned clusters each message matches, including every account's contribution to them. |
| `csm antispam learn --status [<request-id>...]` | Show what the daemon recorded for request IDs, including clusters still publishing; without an ID, list unfinished requests. |
| `csm antispam learn --fresh-namespace` | With learning disabled, move the learning keys and stored messages aside and empty the learning state; the next enable starts a new namespace. |

Each file gets a request ID, printed before it is sent. `csm actions --op integrate.antispam_learn --json` shows its recorded outcome and full digests.

A lost or truncated reply is retried once with the same ID and snapshot.

The exit status is 0 only when every file was learned, already learned, forgotten or matched nothing.

## Stalwart

Prepares a Stalwart mail server for CSM through its admin API. See [Preparing Stalwart](detection-realtime.md#preparing-stalwart).

| Command | Description |
|---------|-------------|
| `csm stalwart setup [--dry-run] [--password-file PATH \| --password-stdin] [--url URL] [--account-domain NAME]` | Configure Stalwart's logging, bans, webmail client addresses, CSM's API key and the `CSM_IP` spam rule. Prints each step as `name: state: detail`. |

### What setup changes

- It makes Stalwart log failed logins and the mail its spam filter rejects or discards.
- It sets Stalwart's ban periods to CSM's block length, so its bans end when CSM's blocks do.
- It makes Stalwart use the client address the web server in front of it reports for webmail logins. CSM's port lock protects that listener, so only the web server can reach it.
- It creates the role `CSM response`, the service account `csm-response` and its API key. See [The service account and its key](#the-service-account-and-its-key).
- It adds the spam rule `CSM_IP`. See [The `CSM_IP` spam rule](#the-csm_ip-spam-rule).

Setup also prints whether the spam filter is on and its scores. An unreadable spam filter status warns without stopping setup.

### The service account and its key

The API key works only from this host and is written to `stalwart.api_key_file`. The `csm-response` account has no password and can receive mail.

- The key steps run only when the API address is on this host.
- A role that lacks CSM's permissions is reset to CSM's list, dropping permissions added by hand.
- A key Stalwart accepts is kept while it is the account's only key. To rotate it, delete the key file and run setup.

Setup refuses an existing `csm-response` account that:

- has a password or another sign-in credential;
- has sign-ins stopped;
- holds keys without CSM's role.

`--account-domain` names the account's domain on a server with several. On a server with tenant administrators, use a domain only the server administrator controls, since whoever can edit the account could give it a password.

### The `CSM_IP` spam rule

`CSM_IP` scores senders on CSM's address list. More of their mail then goes to Junk, or is rejected or discarded at the scores set in Stalwart.

It is the one step that changes how mail is handled. Switching the rule off in Stalwart stops it.

### Admin login

| Source | How setup reads it |
|--------|--------------------|
| Environment | The user from `STALWART_USER` and the password from `STALWART_PASSWORD`. |
| `--password-file` | The password from the first line of the file. |
| `--password-stdin` | The password from the first line of stdin, with the user from `STALWART_USER` or `admin`. |

On a terminal:

- Setup prompts for missing values and hides password input, even with `--password-stdin`.
- When you enter both values, the username is hidden too.
- Press Enter at the user prompt for `admin`.
- Ctrl-D at an empty prompt cancels setup.

Without a terminal, setup reads stdin only with `--password-stdin`.

`--url` overrides `stalwart.api_url`. Before sending the login to an address on this host, setup checks that every socket listening on that port belongs to root or Stalwart's service user. It checks the same for the accepting end of each connection it opens. If setup cannot read who owns them, it does not send the login.

### Setup exit codes

| Exit | Cause |
|------|-------|
| 1 | A setting is unsafe, other Stalwart settings cannot be read, the key file cannot be used or checked, or a change failed. |
| 2 | A usage or config error, an API address that is refused, a missing or refused login, a port held by another user, or a host that is not a Stalwart host. |

## Firewall

See [Firewall](firewall.md) for the full reference.

```bash
csm firewall status
csm firewall deny <ip> [reason]
csm firewall allow <ip> [reason]
csm firewall tempban <ip> <dur> [reason]
csm firewall deny-subnet <cidr> [reason]
csm firewall grep <pattern>
csm firewall flush
csm firewall apply-confirmed <minutes>
csm firewall confirm
csm firewall restart
csm firewall rollback status|confirm|revert
# ...
```

`csm firewall apply-confirmed` and `csm firewall restart` refuse a pending CLI confirmation window and say whether waiting for its rollback still helps. `csm status` and `csm doctor` show the window.

If startup cannot read the window's saved configuration, rollback restores the kernel ruleset and state, and the window stays pending. Once that restore is recorded, later restarts keep the blocks added since and apply the configured settings. You then have two ways to end the window:

- Inspect the current firewall, then run `csm firewall confirm`. It accepts the current ruleset and engine configuration. It does not recover unreadable settings.
- Repair the saved configuration and restart the daemon, which restores it and rebuilds the ruleset with the current blocks.

Removing the saved configuration does not end a recorded window, even one whose marker was empty or corrupt.

See [CLI confirmation window](firewall.md#cli-confirmation-window). The separate Web UI config timer uses `csm firewall rollback`.
