# CLI Commands

## Daemon

| Command | Description |
|---------|-------------|
| `csm daemon` | Run as persistent daemon (fanotify + inotify + PAM + periodic checks) |

## Checks

| Command | Description |
|---------|-------------|
| `csm run` | Run all checks once, send alerts |
| `csm run-critical` | Critical checks only (used by systemd timer) |
| `csm run-deep` | Deep checks only (used by systemd timer) |
| `csm check` | Run all checks, print to stdout (no alerts) |
| `csm check-critical` | Test critical checks only |
| `csm check-deep` | Test deep checks only |
| `csm scan <user>` | Scan single cPanel account |

## Management

| Command | Description |
|---------|-------------|
| `csm install` | Deploy config, systemd, auditd rules, logrotate, WHM plugin |
| `csm uninstall` | Clean removal |
| `csm baseline` | Full server scan, records current state as known-good. Takes 5-10 min on large servers. Required on first install. |
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
| `csm enable --php-shield` | Enable PHP runtime protection |
| `csm disable --php-shield` | Disable PHP runtime protection |

## State database

| Command | Description |
|---------|-------------|
| `csm store compact` | Reclaim unused space in the bbolt state file (atomic rename over the live DB). Requires the daemon to be stopped (`systemctl stop csm`) because bbolt holds an exclusive file lock while running. |
| `csm store compact --preview` | Snapshot into a temp file next to the live DB and print src/dst sizes without replacing anything. Use to estimate reclaim before scheduling a maintenance window. |

## Updates

| Command | Description |
|---------|-------------|
| `csm update-rules` | Download latest signature rules |
| `csm update-geoip` | Update MaxMind GeoLite2 databases |

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
