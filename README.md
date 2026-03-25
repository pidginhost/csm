# CSM — cPanel Security Monitor

Real-time security monitoring for cPanel/WHM shared hosting servers. A single static Go binary that detects compromises, backdoors, and suspicious activity — then alerts you.

Built after a real incident where GSocket reverse shells, LEVIATHAN webshell toolkits, and attacker-created API tokens were found across 6 accounts on a production server.

## Performance

Benchmarked on a production cPanel server with 168 accounts, 275 WordPress sites, 28 million files, and 43,000 directories tracked.

| Tier | Checks | Frequency | Duration | RAM | CPU Priority |
|---|---|---|---|---|---|
| **Critical** | 20 checks | Every 10 min | **< 1 second** | ~55 MB | Normal |
| **Deep** | 10 checks | Every 30 min | **~40 seconds** | ~110 MB | Nice 10 (low) |

**How it stays fast:**
- Pure Go `os.ReadDir` (getdents syscall) instead of `find` — reads directory entries without stat per file
- Directory mtime caching — unchanged directories are skipped entirely, their entries carried forward from the previous scan
- Parallel WordPress checksum verification (5 concurrent workers)
- API tokens read directly from disk instead of spawning 168 `uapi` processes
- Lazy stat — only stat the small subset of files that match suspicious patterns
- State written to disk only when data actually changed (dirty tracking)

**Binary size:** ~7 MB (static, no dependencies)

**Disk usage:**
- Binary: 7 MB (`/opt/csm/csm`)
- State: ~5 MB (`/opt/csm/state/`)
- Logs: rotating, max ~32 MB (`/var/log/csm/`)

## Architecture

CSM runs as two systemd timers:

| Timer | Frequency | What it does |
|---|---|---|
| `csm-critical.timer` | Every 10 min | Process inspection, auth changes, network, firewall |
| `csm-deep.timer` | Every 60 min | Filesystem scans, webshells, .htaccess, WP core |

The binary verifies its own integrity (SHA256) on each run. If tampered with, it sends an alert before doing anything else.

## Security Checks

### Critical Tier (18 checks, every 10 minutes, ~0.5 seconds)

| Check | What it detects |
|---|---|
| Fake kernel threads | Non-root processes with `[bracketed]` names (GSocket, cryptominers) |
| Suspicious processes | Execution from `/tmp`, `/dev/shm`, `/.config/`; reverse shells (`bash -i`, `/dev/tcp/`) |
| PHP process inspection | `lsphp` executing from `/wp-content/uploads/`, `/tmp/`, `/dev/shm/` (active webshell use) |
| Shadow changes | `/etc/shadow` modification — reports which accounts changed and which process did it |
| Root password change | Separate critical alert when root password is changed |
| Bulk password changes | Detects 5+ account passwords changed at once |
| UID 0 accounts | Unauthorized accounts with root privileges |
| SSH keys | Changes to `authorized_keys` for root and all users |
| sshd_config changes | Alerts if PasswordAuthentication or PermitRootLogin changed to 'yes' |
| SSH login anomalies | SSH logins from IPs not in infra_ips |
| API tokens | New WHM root tokens; user tokens with full access and no IP whitelist (read from disk, no process spawning) |
| WHM access monitoring | Password changes and account actions from non-infra IPs in WHM access log |
| Crontabs | Suspicious patterns: `defunct-kernel`, `base64`, reverse shells, bulk downloaders |
| Outbound connections | Connections to known C2 IPs; local backdoor port listeners; outbound to backdoor ports on non-infra IPs |
| User outbound profiling | Non-root user processes connecting to non-standard ports on non-infra IPs |
| DNS connections | Connections to DNS servers not in `/etc/resolv.conf` (DNS tunneling, GSocket relay discovery) |
| Firewall integrity | CSF config changes; backdoor ports in TCP_IN; port 22 re-added |
| Mail queue | Exim queue size spikes (spam from compromised accounts) |
| Per-account email rate | Alerts when a single domain sends >100 emails in recent log window |
| Kernel module audit | Compares loaded kernel modules against baseline — new unknown modules could indicate rootkit |
| MySQL superuser audit | Monitors MySQL users with SUPER privilege — alerts on changes |
| Self-health | Verifies CSM dependencies (exim, auditctl, whmapi1, wp), auditd rules loaded, state dir writable |

### Deep Tier (7 checks, every 30-60 minutes, ~38 seconds)

| Check | What it detects |
|---|---|
| Backdoor binaries | GSocket `defunct` in `.config/htop/`; `gs-netcat`, `gsocket` anywhere in `.config/` |
| Webshell filenames | `h4x0r.php`, `c99.php`, `r57.php`, `wso.php`, `alfa.php`, `b374k.php`, `LEVIATHAN/`, `haxorcgiapi/`, `*.haxor` |
| SUID binaries | SUID files in `/home`, `/tmp`, `/var/tmp`, `/dev/shm` |
| World-writable PHP | PHP files with world-writable permissions (0666, 0777) |
| .htaccess injection | `auto_prepend_file`, `auto_append_file`, `eval`, `base64_decode` in .htaccess (whitelists Wordfence, LiteSpeed, Really Simple Security) |
| WP core integrity | `wp core verify-checksums` across all WordPress installations (5 parallel workers) |
| File index diff | Builds index of PHP/executable files, diffs against previous scan. Catches **new files with unknown names** — not just known patterns. Uses directory mtime caching to skip unchanged dirs. |
| Nulled plugin detection | Scans WordPress plugin PHP files for crack signatures: `nulled by`, `gpl-club`, `license_key_bypass`, `activation_bypass`, etc. |
| RPM binary verification | Verifies critical system packages (openssh-server, shadow-utils, sudo, coreutils) haven't been modified — catches trojaned binaries |
| Group-writable PHP | PHP files writable by web server group (nobody/apache) — allows webshells to persist via HTTP |
| open_basedir verification | Flags accounts with CageFS disabled AND no open_basedir — PHP can read any file on the server |
| Symlink attack detection | Detects symlinks in public_html pointing to other users' directories or sensitive system files (/etc/shadow, /root/) |
| Cross-account correlation | Detects coordinated attacks: 3+ accounts with critical findings, or same malware type across multiple accounts |

### Auto-Response (optional, disabled by default)

| Action | What it does |
|---|---|
| Auto-kill processes | Kills fake kernel threads, reverse shells, GSocket processes (never kills root/system processes) |
| Auto-quarantine files | Moves webshells and backdoor binaries to `/opt/csm/quarantine/` with metadata sidecar |

Enable in config:
```yaml
auto_response:
  enabled: true
  kill_processes: true
  quarantine_files: true
```

### Always-on Features

| Feature | Description |
|---|---|
| Binary self-verification | SHA256 hash check of binary and config on each run |
| auditd rules | 20 kernel-level audit rules monitoring shadow, passwd, SSH, crontab, CSF, and the CSM binary itself |
| Alert rate limiting | Max alerts per hour (default: 10) to prevent email storms |
| Finding deduplication | Same check+message = one alert, not duplicates |
| State tracking | Remembers what it already alerted on — no repeat alerts for known findings |
| History log | Append-only JSONL log of all findings at `/opt/csm/state/history.jsonl` (capped at 10MB) |
| Heartbeat | Dead man's switch ping (healthchecks.io, cronitor) after each run — alerts you if CSM stops running |
| Check timeouts | Individual checks timeout after 5 minutes — prevents hangs |
| Command timeouts | External commands (wp-cli) timeout after 2 minutes with graceful degradation |
| Log rotation | Automatic via logrotate (weekly, 4 rotations, compressed) |
| Lock file | `flock`-based locking prevents concurrent CSM runs from corrupting state |
| Atomic state writes | Writes to temp file then renames — prevents corruption on crash or disk full |
| Signal handling | SIGTERM/SIGINT flushes state to disk before exit |
| Write-on-change | State file only written to disk when data actually changed (dirty tracking with hash comparison) |
| Index validation | Skips diff if current index is empty or <50% of previous — prevents false alert floods from failed scans |
| Directory mtime caching | Unchanged directories carry forward entries from previous scan without re-reading from disk |
| Config validation | `csm validate` checks for common config mistakes before deploying |

## Installation

### From GitLab Package Registry (recommended)

```bash
# First time — requires a project deploy token with read_package_registry scope
GITLAB_TOKEN=xxx /opt/csm/deploy.sh install
# Token is saved for future upgrades
```

### From local build

```bash
make install-remote SERVER=hostalias
```

After install:
1. Edit `/opt/csm/csm.yaml` — set hostname, alert email, infra IPs
2. Run `csm validate` — check config for mistakes
3. Run `csm baseline` — record current state as known-good
4. Run `csm check` — test all checks (prints to stdout, no alerts)

## Upgrading

```bash
/opt/csm/deploy.sh upgrade
```

The upgrade script:
1. Stops both systemd timers
2. Backs up binary and config to `.bak`
3. Downloads new binary from GitLab Package Registry
4. Verifies SHA256 checksum
5. Runs baseline with new binary
6. If baseline fails, rolls back automatically
7. Restarts timers

## Configuration

Config file: `/opt/csm/csm.yaml`

```yaml
hostname: "hostalias.example.com"

alerts:
  email:
    enabled: true
    to: ["admin@example.com"]
    from: "csm@hostalias.example.com"
    smtp: "localhost:25"
  webhook:
    enabled: false
    url: ""
    type: "slack"  # slack, discord, generic
  heartbeat:
    enabled: false
    url: ""  # healthchecks.io / cronitor URL
  max_per_hour: 10  # alert rate limit

integrity:
  binary_hash: ""   # set automatically by baseline
  config_hash: ""   # set automatically by baseline
  immutable: true   # chattr +i on binary

thresholds:
  mail_queue_warn: 500
  mail_queue_crit: 2000
  state_expiry_hours: 24
  deep_scan_interval_min: 60

infra_ips:              # your infrastructure — excluded from network alerts
  - "10.0.0.0/8"

suppressions:
  upcp_window_start: "00:30"   # lower severity during cPanel update window
  upcp_window_end: "02:00"
  known_api_tokens: []         # token names to ignore
  ignore_paths:                # paths excluded from filesystem scans
    - "*/imunify-security/*"
    - "*/cache/*"
    - "*/vendor/*"

c2_blocklist: []               # known attacker IPs
backdoor_ports: [4444, 5555, 55553, 55555, 31337]
```

## Commands

| Command | Description |
|---|---|
| `csm install` | Deploy config, auditd rules, systemd timers, logrotate |
| `csm uninstall` | Clean removal of everything |
| `csm run-critical` | Run critical tier, send alerts (called by 10-min timer) |
| `csm run-deep` | Run deep tier, send alerts (called by 60-min timer) |
| `csm run` | Run all checks, send alerts |
| `csm check` | Run all checks, print to stdout (no alerts sent) |
| `csm check-critical` | Test critical tier only |
| `csm check-deep` | Test deep tier only |
| `csm status` | Show baseline entries and active findings |
| `csm baseline` | Record current state as known-good (stops/restarts timers) |
| `csm validate` | Check config for common mistakes |
| `csm verify` | Verify binary and config integrity |
| `csm version` | Show version, build hash, build date |

## Security

- **Single static binary** — no runtime dependencies, no scripts an attacker can edit
- **Immutable binary** — `chattr +i` set during install, even root can't modify without explicitly removing the flag
- **Self-verification** — SHA256 hash of binary and config checked on every run, tamper alert sent before any other checks
- **auditd integration** — 20 kernel-level rules monitor shadow, passwd, SSH config, crontabs, CSF config, and the CSM binary itself for write/attribute changes
- **Minimal deploy token** — servers use a project deploy token with `read_package_registry` scope only — no access to source code, issues, pipelines, or settings
- **Atomic state writes** — all state files written via temp + rename to prevent corruption
- **Lock file** — prevents concurrent runs from corrupting shared state

**Deploy token setup:**
1. Go to GitLab project > Settings > Repository > Deploy tokens
2. Create token with name `csm-deploy-<hostname>` and scope `read_package_registry`
3. One token per server — revoke individually if compromised

Binary signing with cosign is planned for a future release.

## Development

```bash
make build-linux    # Cross-compile for Linux amd64
make lint           # Run golangci-lint
make test           # Run unit tests
make ci             # All CI checks (fmt, vet, lint, test, build)
make deploy SERVER=hostalias     # scp binary to server
make upgrade SERVER=hostalias    # scp + install + baseline
make tools          # Install golangci-lint and goimports
```

### CI/CD Pipeline (GitLab)

| Stage | Jobs |
|---|---|
| lint | `golangci-lint`, `go vet`, `gofmt` check |
| test | `go test -race` |
| build | Linux amd64 + arm64 static binaries |
| publish | Upload to GitLab Generic Package Registry with SHA256 checksums |
| release | Create GitLab release on tag push (`v*`) |

## Roadmap

- Binary signing with cosign
- Outbound mail content sampling (detect phishing/spam patterns)
- WordPress admin user creation monitoring
- Multi-server config management (Ansible/Salt integration)
- Web dashboard for centralized alert viewing
- Auto-update mechanism (self-upgrade on schedule)
