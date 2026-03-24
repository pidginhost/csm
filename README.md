# CSM — cPanel Security Monitor

Real-time security monitoring for cPanel/WHM shared hosting servers. A single static Go binary that detects compromises, backdoors, and suspicious activity — then alerts you.

Built after a real incident where GSocket reverse shells, LEVIATHAN webshell toolkits, and attacker-created API tokens were found across 6 accounts on a production server.

## Architecture

CSM runs as two systemd timers with separate check tiers:

| Timer | Frequency | Duration | What it does |
|---|---|---|---|
| `csm-critical.timer` | Every 10 min | ~5 seconds | Process inspection, auth changes, network, firewall |
| `csm-deep.timer` | Every 60 min | ~90 seconds | Filesystem scans, webshells, .htaccess, WP core |

The binary verifies its own integrity (SHA256) on each run. If tampered with, it sends an alert before doing anything else.

## Security Checks

### Critical Tier (every 10 minutes)

| Check | What it detects |
|---|---|
| Fake kernel threads | Non-root processes with `[bracketed]` names (GSocket, cryptominers) |
| Suspicious processes | Execution from `/tmp`, `/dev/shm`, `/.config/`; reverse shells |
| PHP process inspection | `lsphp` executing from `/wp-content/uploads/`, `/tmp/`, `/dev/shm/` |
| Shadow changes | `/etc/shadow` modification outside known maintenance windows |
| UID 0 accounts | Unauthorized accounts with root privileges |
| SSH keys | Changes to `authorized_keys` for root and all users |
| API tokens | New WHM root tokens; user tokens with full access and no IP whitelist |
| Crontabs | Suspicious patterns: `defunct-kernel`, `base64`, reverse shells |
| Outbound connections | Connections to known C2 IPs; backdoor port listeners |
| DNS connections | Connections to DNS servers not in `/etc/resolv.conf` (DNS tunneling) |
| Firewall integrity | CSF config changes; backdoor ports in TCP_IN |
| Mail queue | Exim queue size spikes (spam from compromised accounts) |
| Self-health | Verifies CSM dependencies (find, exim, auditctl, whmapi1, wp), auditd rules loaded, state dir writable |

### Deep Tier (every 60 minutes)

| Check | What it detects |
|---|---|
| Backdoor binaries | GSocket `defunct` in `.config/htop/`; `gs-netcat`, `gsocket` |
| Webshell filenames | `h4x0r.php`, `c99.php`, `r57.php`, `wso.php`, `LEVIATHAN/` |
| PHP in uploads | `.php` files in `wp-content/uploads/` (excludes known safe plugin paths) |
| SUID binaries | SUID files in `/home`, `/tmp`, `/var/tmp`, `/dev/shm` |
| .htaccess injection | `auto_prepend_file`, `eval`, `base64_decode` in .htaccess files |
| WP core integrity | `wp core verify-checksums` across all WordPress installations |
| **File index diff** | Builds index of PHP/executable files, diffs against previous scan. Catches NEW files with unknown names — not just known webshell patterns. Detects new PHP in uploads, new executables in .config, suspicious filenames (shell, cmd, eval, random short names). |

### Always-on Features

| Feature | Description |
|---|---|
| Binary self-verification | SHA256 hash check on each run |
| auditd rules | 20 kernel-level audit rules for shadow, passwd, SSH, crontab, CSF |
| Alert rate limiting | Max alerts per hour (default: 10) to prevent storms |
| Finding deduplication | Same check+message only alerts once per run |
| State tracking | No repeat alerts for known findings |
| History log | Append-only JSONL log of all findings (capped at 10MB) |
| Heartbeat | Dead man's switch ping after each run |
| Check timeouts | Individual checks timeout after 5 minutes |
| Command timeouts | External commands timeout after 2 minutes |
| Log rotation | Automatic via logrotate (weekly, 4 rotations) |
| Lock file | `flock`-based locking prevents concurrent CSM runs from corrupting state |
| Atomic state writes | Writes to temp file then renames — prevents corruption on crash/disk full |
| Signal handling | SIGTERM/SIGINT flushes state to disk before exit |
| Write-on-change | State file only written when data actually changed (dirty tracking) |
| Index validation | Skips diff if current index is empty or <50% of previous (prevents false alert floods) |
| Self-health check | Verifies CSM dependencies (find, exim, whmapi1, wp, auditctl), auditd rules, state dir |
| Config validation | `csm validate` checks hostname, alert methods, email recipients, webhook URL |

## Installation

### From GitLab CI artifacts

```bash
# First time (requires GitLab token with read_api scope)
GITLAB_TOKEN=glpat-xxx /opt/csm/deploy.sh install

# Token is saved for future upgrades
```

### From local build

```bash
make install-remote SERVER=cluster6
```

After install:
1. Edit `/opt/csm/csm.yaml` — set hostname, alert email, infra IPs
2. Run `csm validate` — check config for mistakes
3. Run `csm baseline` — record current state as known-good
4. Run `csm check` — test all checks

## Upgrading

```bash
/opt/csm/deploy.sh upgrade
```

The upgrade script stops timers, backs up binary+config, swaps, baselines, and restarts. If baseline fails, it rolls back automatically.

## Configuration

Config file: `/opt/csm/csm.yaml`

```yaml
hostname: "cluster6.example.com"

alerts:
  email:
    enabled: true
    to: ["admin@example.com"]
    from: "csm@cluster6.example.com"
    smtp: "localhost:25"
  webhook:
    enabled: false
    url: ""
    type: "slack"  # slack, discord, generic
  heartbeat:
    enabled: false
    url: ""  # healthchecks.io / cronitor URL
  max_per_hour: 10

integrity:
  binary_hash: ""   # set by baseline
  config_hash: ""   # set by baseline
  immutable: true

thresholds:
  mail_queue_warn: 500
  mail_queue_crit: 2000
  state_expiry_hours: 24
  deep_scan_interval_min: 60

infra_ips:
  - "10.0.0.0/8"

suppressions:
  upcp_window_start: "00:30"
  upcp_window_end: "02:00"
  known_api_tokens: []
  ignore_paths:
    - "*/imunify-security/*"
    - "*/cache/*"
    - "*/vendor/*"

c2_blocklist: []
backdoor_ports: [4444, 5555, 55553, 55555, 31337]
```

## Commands

| Command | Description |
|---|---|
| `csm install` | Deploy config, auditd rules, systemd timers, logrotate |
| `csm uninstall` | Clean removal |
| `csm run-critical` | Run critical tier, send alerts (10-min timer) |
| `csm run-deep` | Run deep tier, send alerts (60-min timer) |
| `csm run` | Run all checks, send alerts |
| `csm check` | Run all checks, print to stdout (no alerts) |
| `csm check-critical` | Test critical tier |
| `csm check-deep` | Test deep tier |
| `csm status` | Show baseline and active findings |
| `csm baseline` | Record current state as known-good |
| `csm validate` | Check config for mistakes |
| `csm verify` | Verify binary and config integrity |
| `csm version` | Show version and build info |

## Security Notes

- Single static binary — no runtime dependencies
- `chattr +i` (immutable flag) prevents modification
- Self-verification on every run (SHA256)
- auditd monitors the binary and config for tampering
- Deploy token at `/opt/csm/.deploy-token` (root-only, mode 600)

**Use project-scoped deploy tokens** (Settings > Repository > Deploy tokens, `read_package_registry` scope only) instead of personal access tokens. The server only downloads published binaries — no access to source code.

Binary signing with cosign is planned for a future release.

## Development

```bash
make build-linux    # Build for Linux
make lint           # Run golangci-lint
make test           # Run tests
make ci             # All CI checks
make deploy SERVER=cluster6     # Deploy binary
make upgrade SERVER=cluster6    # Upgrade existing
make tools          # Install dev tools
```

## Roadmap

- Binary signing with cosign
- Outbound mail content sampling
- WordPress admin user creation monitoring
- Multi-server management (Ansible/Salt)
- Web dashboard for centralized alerts
- Auto-update mechanism
