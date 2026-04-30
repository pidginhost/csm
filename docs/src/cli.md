# CLI Commands

## Daemon

| Command | Description |
|---------|-------------|
| `csm daemon` | Run as persistent daemon (fanotify + inotify + PAM + periodic checks) |

## Checks

| Command | Description |
|---------|-------------|
| `csm run` | Run all checks now via the daemon, send alerts |
| `csm run-critical` | Critical checks now via the daemon (the daemon also schedules critical checks internally every 10 min) |
| `csm run-deep` | Deep checks now via the daemon (the daemon also schedules deep checks internally every 60 min) |
| `csm check` | Run all checks via the daemon, print findings to stdout, no alerts / auto-response |
| `csm check-critical` | Test critical checks only (dry-run via daemon) |
| `csm check-deep` | Test deep checks only (dry-run via daemon) |
| `csm scan <user>` | Scan single cPanel account |

## Management

| Command | Description |
|---------|-------------|
| `csm install` | Deploy config, systemd, auditd rules, logrotate, WHM plugin |
| `csm uninstall` | Clean removal |
| `csm baseline` | Full server scan via the daemon, records current state as known-good. Takes 5-10 min on large servers. Required on first install. Add `--confirm` when existing history would be cleared. The daemon must be running (phase 2: baseline is coordinated inside the daemon, no longer needs systemd timers stopped first). |
| `csm rehash` | Update binary/config hashes without scanning. Use after config edits. Run twice (circular hash). |
| `csm status` | Show current state, last run, active findings |
| `csm validate` | Validate config (`--deep` for connectivity probes) |
| `csm config show` | Display config with secrets redacted |
| `csm verify` | Verify binary and config integrity |
| `csm version` | Version and build info |

## Remediation

| Command | Description |
|---------|-------------|
| `csm clean <path>` | Clean infected PHP file (backs up original) |
| `csm db-clean --option <account> <option_name> [--preview]` | Sanitize malicious WordPress option values (e.g. injected `siteurl` / `home`) |
| `csm db-clean --revoke-user <account> <user_id> [--demote] [--preview]` | Revoke or demote a compromised WordPress admin and invalidate their sessions |
| `csm db-clean --delete-spam <account> [--preview]` | Purge spam comments and trackbacks from a WordPress account |
| `csm db-clean --drop-object <account> <schema> <type> <name> [--preview]` | Drop a MySQL trigger / event / stored procedure / stored function, capturing its CREATE SQL into the `db_object_backups` bbolt bucket first. `<type>` must be `trigger`, `event`, `procedure`, or `function`. `<schema>` must match a database discovered for `<account>`. Daemon must be stopped. |
| `csm enable --php-shield` | Enable PHP runtime protection |
| `csm disable --php-shield` | Disable PHP runtime protection |

## State database

| Command | Description |
|---------|-------------|
| `csm store compact` | Reclaim unused space in the bbolt state file (atomic rename over the live DB). Requires the daemon to be stopped (`systemctl stop csm`) because bbolt holds an exclusive file lock while running. |
| `csm store compact --preview` | Snapshot into a temp file next to the live DB and print src/dst sizes without replacing anything. Use to estimate reclaim before scheduling a maintenance window. |
| `csm store export <path>` | Write a tar+zstd backup containing the bbolt store, the state directory, and the signature-rules cache. A sibling `<path>.sha256` companion file holds the archive hash for verification. Daemon must be running. |
| `csm store import <path>` | Restore from a backup archive. Daemon must be stopped. Default restores everything; `--only=baseline` restores only state JSON files (file hashes); `--only=firewall` merges only firewall buckets into the existing bbolt; `--force-platform-mismatch` allows restoring an archive captured on a different OS / panel / web server. |
| `csm export --since <when>` | Dump audit-log events for SIEM backfill. `<when>` is RFC 3339 (`2026-04-01T00:00:00Z`) or a duration relative to now (`24h`, `7d`). One JSON event per line on stdout, in the same `v=1` schema the live audit_log sinks emit. Pipe to a file or directly into a log shipper. Daemon must be running. |

## Updates

| Command | Description |
|---------|-------------|
| `csm update-rules` | Download latest signature rules |
| `csm update-geoip` | Update MaxMind GeoLite2 databases |

## PHP-relay (mail abuse, cPanel only)

Operator controls for the email PHP-relay detector. Talks to the daemon's control socket; the daemon must be running. See [Real-time detection](detection-realtime.md#php-relay-mail-abuse-cpanel-only) for what the detector fires on, and [Auto-response](auto-response.md#auto-freeze-php-relay) for the freeze action.

| Command | Description |
|---------|-------------|
| `csm phprelay status` | Print the detector's current state as JSON: enabled, platform, effective dry-run + source (runtime/bbolt/csm.yaml), Path 2b effective account limit, scripts/IPs/accounts tracked, msgID-index size, active ignores. Use to confirm the watcher is wired on a fresh install. |
| `csm phprelay ignore-script <scriptKey> [--for-hours N] [--persist] [--reason ...]` | Suppress all 4 paths for a `host:/path` scriptKey. Default TTL 168h (7d). `--persist` writes to the bbolt `phprelay:ignore` bucket so the suppression survives daemon restarts; without it the entry is in-memory only. `<scriptKey>` is the value the daemon prints in `email_php_relay_abuse` findings (e.g. `shop.example.com:/wp-admin/admin-ajax.php`). |
| `csm phprelay unignore <scriptKey> [--persist]` | Remove an active ignore. `--persist` also deletes the bbolt row. |
| `csm phprelay ignore-list` | List all active ignores as JSON: scriptKey, expiresAt, addedBy, reason. |
| `csm phprelay dry-run on\|off\|reset [--persist]` | Override the auto-freeze dry-run state at runtime. `on` = freeze findings emitted but no `exim -Mf` runs; `off` = live freezes; `reset` clears the runtime override and falls back to bbolt or `csm.yaml`. Precedence: runtime > bbolt > yaml. `--persist` writes the `on`/`off` choice to the bbolt `phprelay:settings` bucket so it survives restarts; on `reset --persist` the bbolt row is also deleted. |
| `csm phprelay thaw <msgID>` | Manually thaw a frozen Exim message. Wraps `exim -Mt` with msgID validation (rejects anything that isn't `[A-Za-z0-9-]{16,32}`) and writes a `thaw` entry to the auto-freeze JSONL audit at `/var/log/csm/php_relay_audit.jsonl`. |

## Firewall

23 subcommands. See [Firewall](firewall.md) for the full reference.

```bash
csm firewall status
csm firewall deny <ip> [reason]
csm firewall allow <ip> [reason]
csm firewall tempban <ip> <dur> [reason]
csm firewall deny-subnet <cidr> [reason]
csm firewall grep <pattern>
csm firewall flush
# ...
```
