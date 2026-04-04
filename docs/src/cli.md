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
| `csm baseline` | Record current state as known-good |
| `csm rehash` | Update binary/config hashes without scanning |
| `csm status` | Show current state, last run, active findings |
| `csm validate` | Validate config (`--deep` for connectivity probes) |
| `csm config show` | Display config with secrets redacted |
| `csm verify` | Verify binary and config integrity |
| `csm version` | Version and build info |

## Remediation

| Command | Description |
|---------|-------------|
| `csm clean <path>` | Clean infected PHP file (backs up original) |
| `csm enable --php-shield` | Enable PHP runtime protection |
| `csm disable --php-shield` | Disable PHP runtime protection |

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
