# CSM — cPanel Security Monitor

Real-time security monitoring for cPanel/WHM shared hosting servers. A single static Go binary with a persistent daemon that detects compromises, backdoors, and suspicious activity in **real-time** — then alerts you within seconds.

Built after a real incident where GSocket reverse shells, LEVIATHAN webshell toolkits, and attacker-created API tokens were found across 6 accounts on a production server.

## Performance

Benchmarked on a production cPanel server with 168 accounts, 275 WordPress sites, and 28 million files.

### Daemon Mode (recommended)

| Component | Detection Speed | Resource Usage |
|---|---|---|
| **fanotify file monitor** | **< 1 second** | < 0.1% CPU idle, ~5 MB |
| **inotify log watchers** | **~2 seconds** | < 0.1% CPU idle, ~1 MB |
| **Critical periodic checks** | Every 10 min, < 1 sec | ~35 MB peak |
| **Deep periodic checks** | Every 60 min, ~40 sec | ~100 MB peak |
| **Daemon idle** | — | **45 MB resident**, < 0.1% CPU |

### Timer Mode (legacy, still supported)

| Tier | Checks | Frequency | Duration | RAM |
|---|---|---|---|---|
| Critical | 22 checks | Every 10 min | < 1 second | ~35 MB |
| Deep | 12 checks | Every 60 min | ~40 seconds | ~100 MB |

**How it stays fast:**
- **fanotify** — kernel-level file event monitoring on mount points, zero polling
- **inotify** — tail-follow on log files, 2-second poll interval
- Pure Go `os.ReadDir` (getdents syscall) — reads directory entries without stat per file
- Directory mtime caching — unchanged directories are skipped entirely
- Parallel WordPress checksum verification (5 concurrent workers)
- API tokens read directly from disk (no process spawning)
- Lazy stat — only stat files that match suspicious patterns
- State written to disk only when changed (dirty tracking)
- Alert batching — 5-second window to group related findings
- Analyzer worker pool with backpressure (bounded queue, overflow detection)

**Binary size:** ~8 MB (static, no dependencies)

**Disk usage:**
- Binary: 8 MB (`/opt/csm/csm`)
- State: ~5 MB (`/opt/csm/state/`)
- Logs: rotating, max ~32 MB (`/var/log/csm/`)

## Architecture

CSM runs as a persistent daemon with three detection layers:

```
csm daemon
│
├── Real-time: fanotify File Monitor
│   Watches /home, /tmp, /dev/shm mount points
│   Detects file creation/modification in < 1 second
│   3 analyzer workers with bounded queue
│
├── Real-time: inotify Log Watchers
│   Tails session_log, access_log, secure, exim_mainlog, messages
│   Detects logins, uploads, SSH, FTP, API failures in ~2 seconds
│
├── Periodic: Critical Scanner (every 10 min)
│   Processes, network, tokens, firewall, kernel modules
│
├── Periodic: Deep Scanner (every 60 min)
│   WP core checksums, RPM integrity, nulled plugins,
│   open_basedir, symlinks (only checks fanotify can't do)
│
├── Alert Dispatcher
│   Batching, deduplication, rate limiting, auto-response
│
└── Integrity + Heartbeat + Watchdog
```

Falls back to timer-based mode if the kernel doesn't support fanotify.

## Detection Speed

| Event | Timer Mode | Daemon Mode |
|---|---|---|
| Webshell file created | 60 min | **< 1 second** |
| PHP dropper with remote payload | 60 min | **< 1 second** |
| .htaccess injection | 60 min | **< 1 second** |
| Executable created in .config | 60 min | **< 1 second** |
| cPanel login from attacker IP | 10 min | **~2 seconds** |
| File Manager upload | 10 min | **~2 seconds** |
| SSH login from unknown IP | 10 min | **~2 seconds** |
| Password change | 10 min | **~2 seconds** |
| Phishing page uploaded | 60 min | **< 1 second** |
| Credential harvest log created | 60 min | **< 1 second** |
| Fake kernel thread started | 10 min | 10 min |
| WP core file modified | 60 min | 60 min |

## Security Checks

### Real-time: fanotify File Monitor

| Check | What it detects |
|---|---|
| Webshell creation | Known webshell filenames (h4x0r.php, c99.php, etc.) created anywhere in /home |
| PHP in uploads | PHP files created in wp-content/uploads/ |
| PHP in sensitive WP dirs | PHP files in wp-content/languages/ or wp-content/upgrade/ (LEVIATHAN attack vector) |
| Executable in .config | Executable files created in user .config directories (GSocket backdoor pattern) |
| .htaccess injection | .htaccess modified with auto_prepend_file, eval, base64_decode |
| PHP content analysis | Obfuscated PHP: remote payload URLs, eval+decode chains, goto spaghetti, shell execution with request input |
| PHP config tampering | .user.ini modified to disable security functions (disable_functions cleared, allow_url_include enabled) |
| Suspicious extensions | .haxor, .cgix, .phtml, .pht, .php5 files created |
| HTML phishing pages | Brand impersonation (Microsoft/Google/Dropbox/etc.) + credential harvesting + redirect/exfiltration |
| Credential harvest logs | Files like results.txt, data.txt with email:password pairs (phishing kit output) |
| Phishing kit ZIPs | ZIP archives with brand-related names (office365.zip, sharepoint.zip) uploaded to public_html |
| Signature rule matches | External YAML signature rules scanned against new PHP files in real-time |

### Real-time: inotify Log Watchers

| Check | What it detects |
|---|---|
| cPanel login | cPanel logins from non-infra IPs (session_log) |
| cPanel password purge | Session purge from password change (Imunify auto-response or attacker) |
| File Manager upload | File Manager write operations from non-infra IPs (access_log) |
| SSH login | SSH logins from unknown IPs (/var/log/secure) |
| Exim anomalies | Frozen bounce messages (exim_mainlog) |
| FTP login/auth failure | FTP logins and failed auth from non-infra IPs (/var/log/messages) |
| cPanel API failures | API authentication failures (401/403) in real-time |
| Webmail login attempts | Webmail login attempts from non-infra IPs |

### Periodic: Critical Tier (28 checks, every 10 minutes, < 1 second)

| Check | What it detects |
|---|---|
| Fake kernel threads | Non-root processes with `[bracketed]` names (GSocket, cryptominers) |
| Suspicious processes | Execution from `/tmp`, `/dev/shm`, `/.config/`; reverse shells |
| PHP process inspection | `lsphp` executing from uploads, /tmp, /dev/shm (active webshell use) |
| Shadow changes | Password changes — reports which accounts changed and which process did it |
| Root password change | Separate CRITICAL alert when root password is changed |
| Bulk password changes | 5+ account passwords changed at once |
| UID 0 accounts | Unauthorized root-level accounts |
| SSH keys | Changes to authorized_keys for root and all users |
| sshd_config changes | PasswordAuthentication or PermitRootLogin changed to 'yes' |
| SSH login anomalies | SSH logins from non-infra IPs |
| API tokens | New WHM/cPanel tokens with full access and no IP whitelist |
| WHM access monitoring | Password changes and account actions from non-infra IPs |
| cPanel login monitoring | cPanel logins from non-infra IPs, multi-IP correlation (credential stuffing) |
| cPanel File Manager | File uploads/edits via File Manager from non-infra IPs |
| Crontabs | Suspicious patterns: defunct-kernel, base64, reverse shells |
| Outbound connections | C2 IPs, backdoor port listeners, suspicious user outbound connections |
| DNS connections | Connections to non-configured DNS resolvers (DNS tunneling) |
| Firewall integrity | CSF config changes, backdoor ports in TCP_IN |
| Mail queue + per-account rate | Queue spikes and single-domain email bursts (>100 messages) |
| Kernel module audit | New modules loaded after baseline (rootkit detection) |
| MySQL superuser audit | Changes to MySQL users with SUPER privilege |
| Database dump detection | mysqldump/pg_dump running under non-root users (data exfiltration) |
| Outbound paste sites | Processes connecting to pastebin.com, transfer.sh, gist.githubusercontent.com, etc. |
| wp-login.php brute force | >20 POST requests to wp-login.php from single IP |
| xmlrpc.php abuse | >30 POST requests to xmlrpc.php (brute force or amplification) |
| WordPress user enumeration | Requests to /wp-json/wp/v2/users or ?author= (username discovery) |
| FTP login monitoring | FTP logins from non-infra IPs and brute force (>10 failed per IP) |
| Webmail brute force | Login brute force on ports 2095/2096 |
| cPanel API auth failures | Failed API authentication (401/403) from non-infra IPs |
| Self-health | Dependency verification, auditd rules, state dir |

### Periodic: Deep Tier (8 checks when daemon active, 15 when timer mode)

When the daemon is running with fanotify, only checks that fanotify can't replace run periodically:

| Check | What it detects |
|---|---|
| WP core integrity | `wp core verify-checksums` across all WordPress installations (5 parallel workers) |
| Nulled plugin detection | Crack signatures in WordPress plugin files |
| RPM binary verification | Modified system binaries (openssh-server, sudo, coreutils) |
| open_basedir verification | Accounts with CageFS disabled and no open_basedir |
| Symlink attack detection | Symlinks pointing to other users' directories or /etc/shadow |
| WAF engine mode | Alerts if ModSecurity is in DetectionOnly mode (logging but not blocking) |
| WAF rule staleness | Alerts if vendor rules haven't been updated in 30+ days |
| WAF per-account bypass | Detects domains with ModSecurity disabled |
| PHP configuration changes | .user.ini changes: disable_functions cleared, allow_url_include enabled, open_basedir removed |
| Phishing page detection | 8-layer detection: brand impersonation, credential harvesting, structural analysis, directory anomalies, PHP phishing, open redirectors, credential logs, kit archives |
| PHP content analysis | Obfuscated droppers: goto spaghetti, hex strings, call_user_func construction, remote payload URLs |
| Signature rule scanning | External YAML rules scanned against files in sensitive directories |
| WP database injection | `<script>`, `eval()`, `base64_decode` in wp_posts and wp_options content |
| WP siteurl hijacking | Malicious code injected into WordPress siteurl/home options |
| WP rogue admin accounts | New administrator accounts created in the last 7 days |
| WP suspicious admin email | Admin accounts using disposable/temporary email domains |
| WP spam injection | Pharma/casino/gambling spam content in published posts |
| DNS zone modifications | Changes to /var/named/*.db zone files (DNS hijacking) |
| SSL certificate issuance | New certificates via AutoSSL (phishing domain certs) |

### Auto-Response (optional, disabled by default)

| Action | What it does |
|---|---|
| Auto-kill processes | Kills fake kernel threads, reverse shells, GSocket (never kills root/system) |
| Auto-quarantine files | Moves webshells/backdoors/phishing to `/opt/csm/quarantine/` with metadata sidecar |
| Auto-block IPs | Blocks attacker IPs via CSF with configurable expiry (brute-force, C2, credential stuffing) |
| Malware cleaning | Surgical removal of @include injections, prepend/append injections, inline eval chains. Backup created before any change. |

```yaml
auto_response:
  enabled: true
  kill_processes: true
  quarantine_files: true
```

### Always-on Features

| Feature | Description |
|---|---|
| Binary self-verification | SHA256 hash check on each run/startup |
| auditd rules | 20 kernel-level audit rules for shadow, passwd, SSH, crontab, CSF |
| Alert rate limiting | Max alerts per hour (default: 10) |
| Alert batching | 5-second window to group related findings (daemon mode) |
| Finding deduplication | Same check+message = one alert |
| Sensitive data redaction | Passwords and tokens redacted from alert emails |
| State tracking | No repeat alerts for known findings |
| History log | Append-only JSONL at `/opt/csm/state/history.jsonl` (capped 10MB) |
| Heartbeat | Dead man's switch ping after each periodic scan |
| Check timeouts | 5 minutes per check |
| Command timeouts | 2 minutes for external commands (wp-cli) |
| Log rotation | logrotate (weekly, 4 rotations, compressed) |
| Lock file | flock prevents concurrent state corruption |
| Atomic state writes | temp + rename prevents corruption |
| Signal handling | SIGTERM/SIGINT flushes state |
| Write-on-change | Dirty tracking with hash comparison |
| Event overflow detection | Alerts when fanotify queue overflows (event storms) |
| systemd watchdog | Auto-restart if daemon stops responding |
| Cross-account correlation | 3+ accounts with CRITICAL findings = coordinated attack alert |

## Installation

### From GitLab Package Registry

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
4. Start daemon: `systemctl start csm.service`

## Running Modes

### Daemon Mode (recommended)

```bash
csm daemon
# Or via systemd:
systemctl enable csm.service
systemctl start csm.service
```

Real-time detection via fanotify + inotify. Falls back to periodic-only if fanotify unavailable.

### Timer Mode (legacy)

Two systemd timers: `csm-critical.timer` (10 min) and `csm-deep.timer` (60 min). Use if daemon mode isn't suitable.

## Upgrading

```bash
/opt/csm/deploy.sh upgrade
```

Stops daemon/timers, backs up, downloads, verifies checksum, baselines, restarts. Rolls back on failure.

## Signature Rules

CSM supports external malware signature rules in YAML format, loaded from `/opt/csm/rules/`. Rules are scanned against new files in real-time (fanotify) and during deep scans.

```yaml
# /opt/csm/rules/malware.yml
version: 1
updated: "2026-03-26"

rules:
  - name: webshell_c99
    description: "C99 webshell"
    severity: critical
    category: webshell
    file_types: [".php"]
    patterns: ["c99shell", "c99_buff_prepare"]   # literal (case-insensitive)
    min_match: 1

  - name: php_eval_decode
    description: "Obfuscated PHP eval chain"
    severity: critical
    category: dropper
    file_types: [".php"]
    patterns: ["eval("]
    regexes: ["(?:base64_decode|gzinflate|gzuncompress)"]  # regex
    min_match: 2
```

**Update rules:** `csm update-rules` downloads latest rules from the configured URL. The running daemon reloads rules on `SIGHUP`:

```bash
csm update-rules
kill -HUP $(pidof csm)    # reload without restart
```

A default rule set with 25+ rules ships in `configs/malware.yml`, covering webshells, backdoors, droppers, phishing kits, CGI abuse, credential harvesters, and exploits.

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
  max_per_hour: 10

auto_response:
  enabled: false
  kill_processes: false
  quarantine_files: false
  block_ips: false
  block_expiry: "24h"

signatures:
  rules_dir: "/opt/csm/rules"
  update_url: ""  # URL to download latest rules

integrity:
  binary_hash: ""   # set by baseline
  config_hash: ""   # set by baseline
  immutable: true

thresholds:
  mail_queue_warn: 500
  mail_queue_crit: 2000
  state_expiry_hours: 24
  deep_scan_interval_min: 60
  multi_ip_login_threshold: 3
  multi_ip_login_window_min: 60

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
| `csm daemon` | Run as persistent daemon (real-time + periodic) |
| `csm install` | Deploy config, auditd rules, systemd service, logrotate |
| `csm uninstall` | Clean removal |
| `csm run` | Run all checks once, send alerts |
| `csm run-critical` | Run critical tier once |
| `csm run-deep` | Run deep tier once |
| `csm check` | Run all checks, print to stdout (no alerts) |
| `csm check-critical` | Test critical tier |
| `csm check-deep` | Test deep tier |
| `csm status` | Show baseline and active findings |
| `csm baseline` | Record current state as known-good |
| `csm validate` | Check config for mistakes |
| `csm verify` | Verify binary and config integrity |
| `csm update-rules` | Download latest malware signature rules |
| `csm clean <path>` | Clean an infected PHP file — removes injections, creates backup |
| `csm version` | Show version and build info |

## Security

- **Single static binary** — no dependencies, no scripts to edit
- **Immutable binary** — `chattr +i`, can't modify without explicitly removing
- **Self-verification** — SHA256 on every startup and periodic check
- **auditd integration** — 20 kernel rules monitor the CSM binary itself
- **Minimal deploy token** — `read_package_registry` scope only, no source code access
- **Atomic writes** — temp + rename on all state files
- **Sensitive data redaction** — passwords and tokens redacted from alert emails
- **systemd watchdog** — auto-restart if daemon stops responding

**Deploy token:** Project > Settings > Repository > Deploy tokens → `read_package_registry` scope. One token per server.

## Development

```bash
make build-linux    # Cross-compile for Linux amd64
make lint           # golangci-lint (runs as GOOS=linux for fanotify)
make test           # Unit tests
make ci             # All CI checks
make deploy SERVER=hostalias
make tools          # Install dev tools
```

### CI/CD Pipeline (GitLab)

| Stage | Jobs |
|---|---|
| lint | golangci-lint, go vet, gofmt |
| test | go test -race |
| build | Linux amd64 + arm64 static binaries |
| publish | GitLab Generic Package Registry + SHA256 checksums |
| release | GitLab release on tag push (v*) |

## Roadmap

- YARA-X integration (VirusTotal's next-gen YARA engine) for advanced malware signatures
- PHP runtime protection via auto_prepend_file security handler
- PAM integration for real-time brute-force blocking (seconds, not minutes)
- WAF rule management and custom ModSecurity rule deployment
- Web dashboard (WHM plugin) for centralized management
- CAPTCHA/challenge pages instead of hard IP blocks
- Binary signing with cosign
- Multi-server config management
