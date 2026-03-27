# CSM — cPanel Security Monitor

Real-time security monitoring for cPanel/WHM shared hosting servers. A single static Go binary with a persistent daemon that detects compromises, backdoors, phishing, and suspicious activity in **real-time** — then alerts you within seconds.

Designed as a full Imunify360 replacement. 48 security checks, 14 real-time detection types, 6 log watchers, 47 malware signature rules, PHP runtime protection, PAM brute-force integration, 7-strategy malware cleaning, IP blocking, outbound email scanning, per-account on-demand scanning, and a web dashboard with real-time WebSocket feed.

Built after real incidents where GSocket reverse shells, LEVIATHAN webshell toolkits, credential-stuffed cPanel accounts, and phishing kits were found across 12+ accounts on production servers.

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

**Codebase:** 96 Go files, ~22,600 lines of code, 3 dependencies (yaml.v3, yara-x, google/nftables)

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
├── nftables Firewall Engine
│   Replaces CSF. Atomic rules, per-IP metering, IPv6,
│   SMTP block, country block, subnet block, DynDNS
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
| YARA-X rule matches | YARA-X rules scanned against new files (optional, build with `-tags yara`) |

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

### Periodic: Critical Tier (30 checks, every 10 minutes, < 1 second)

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
| Firewall integrity | nftables ruleset hash monitoring, backdoor ports in TCP_IN |
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

### Periodic: Deep Tier (5 checks when daemon active, 17 when timer mode)

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
| Outbound email scanning | Samples email headers/body for phishing URLs, Reply-To mismatch, brand spoofing, suspicious mailers |
| DNS zone modifications | Changes to /var/named/*.db zone files (DNS hijacking) |
| SSL certificate issuance | New certificates via AutoSSL (phishing domain certs) |

### Auto-Response (optional, disabled by default)

| Action | What it does |
|---|---|
| Auto-kill processes | Kills fake kernel threads, reverse shells, GSocket (never kills root/system) |
| Auto-quarantine files | Moves webshells/backdoors/phishing to `/opt/csm/quarantine/` with metadata sidecar |
| Auto-block IPs | Blocks attacker IPs via nftables firewall engine with configurable expiry (brute-force, C2, credential stuffing). Falls back to CSF if firewall disabled. |
| Malware cleaning | 7 strategies: @include injection, prepend/append injection, inline eval, multi-layer base64 chains, chr()/pack() code construction, hex-encoded variable injection. Plus DB spam cleaning. Backup created before any change. |
| PHP runtime shield | `auto_prepend_file` protection — blocks PHP execution from uploads/tmp, detects webshell parameters, logs suspicious POST requests |
| PAM brute-force | Real-time login failure tracking via Unix socket — blocks IPs within seconds of threshold breach (SSH, FTP, email) |

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
| auditd rules | 20 kernel-level audit rules for shadow, passwd, SSH, crontab |
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
make install-remote SERVER=cluster6
```

After install:
1. Edit `/opt/csm/csm.yaml` — set hostname, alert email, infra IPs
2. Run `csm validate` — check config for mistakes
3. Run `csm baseline` — record current state as known-good
4. Start daemon: `systemctl start csm.service`

### Optional: PHP Runtime Shield

```bash
csm install --php-shield
```

Deploys a lightweight PHP `auto_prepend_file` that:
- Blocks direct PHP execution from `wp-content/uploads/`, `/tmp/`, `/dev/shm/`
- Detects webshell command parameters (`?cmd=`, `?exec=`) in requests
- Logs suspicious POST requests with base64-encoded bodies
- Reports events to the daemon via `/var/run/csm/php_events.log` for real-time alerting

Overhead: < 0.1ms per request. Fails open — if the shield file is deleted, PHP continues normally.

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

**Update rules:** `csm update-rules` downloads latest rules from the configured URL. The running daemon reloads signature rules + firewall ruleset on `SIGHUP`:

```bash
csm update-rules
kill -HUP $(pidof csm)    # reload without restart
```

A default rule set with 25+ rules ships in `configs/malware.yml`, covering webshells, backdoors, droppers, phishing kits, CGI abuse, credential harvesters, and exploits.

### YARA-X Integration (optional)

CSM supports [YARA-X](https://virustotal.github.io/yara-x/) (VirusTotal's next-gen YARA engine) for advanced malware signatures. Place `.yar` files in `/opt/csm/rules/` alongside YAML rules.

```bash
# Build with YARA-X support (requires yara-x native library)
go build -tags yara ./cmd/csm

# Without -tags yara, YARA-X is disabled (default — keeps static binary)
go build ./cmd/csm
```

YARA rules run in parallel with YAML signature rules. Both are reloaded on `SIGHUP`. A default YARA rule file ships in `configs/malware.yar` with 25+ rules covering webshells, backdoors, droppers, phishing, CGI abuse, and exploits.

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

auto_response:
  enabled: false
  kill_processes: false
  quarantine_files: false
  block_ips: false
  block_expiry: "24h"
  netblock: false             # auto-block /24 subnet when 3+ IPs from same range
  netblock_threshold: 3

firewall:
  enabled: false              # enable to activate nftables firewall (replaces CSF)
  ipv6: false                 # enable IPv6 dual-stack filtering
  conn_rate_limit: 30         # new connections per minute per IP
  syn_flood_protection: true
  conn_limit: 50              # max concurrent connections per IP
  udp_flood: true
  smtp_block: false           # restrict outbound SMTP to allowed users
  # dyndns_hosts: ["myhost.dyndns.org"]

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
| `csm scan <user>` | Scan a single cPanel account (16 checks, ~5 sec). Add `--alert` to send alerts |
| `csm firewall ...` | Firewall management — see [nftables Firewall Engine](#nftables-firewall-engine) below |
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
make build-linux    # Cross-compile for Linux amd64 (no YARA-X)
# make build-yara   # Build with YARA-X support (requires yara-x native lib)
make lint           # golangci-lint (runs as GOOS=linux for fanotify)
make test           # Unit tests
make ci             # All CI checks
make deploy SERVER=cluster6
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

## Web UI Dashboard

Embedded HTTPS dashboard with real-time WebSocket feed, active findings, history, and quarantine management.

```yaml
# /opt/csm/csm.yaml
webui:
  enabled: true
  listen: "localhost:9443"
  auth_token: "your-secret-token"
  # tls_cert: ""  # optional: custom cert path
  # tls_key: ""   # optional: custom key path
  # ui_dir: "/opt/csm/ui"  # path to frontend files (default)
```

Access at `https://localhost:9443/login`. Auto-generates a self-signed TLS cert on first start. Frontend files are loaded from `/opt/csm/ui/` — if missing, only the API is available.

**Pages:**
- **Dashboard** — summary cards, 24-hour findings timeline chart (SVG), fanotify status, live WebSocket feed with expandable details
- **Findings** — active findings with search/filter, per-finding Fix button (chmod, quarantine, kill+quarantine), bulk select + Fix Selected, dismiss buttons, per-account scan form
- **History** — paginated history with severity dropdown filter, click-to-expand finding details, CSV export button
- **Quarantine** — quarantined file list with one-click restore to original location
- **Blocked IPs** — view/manage blocked IPs (nftables or CSF), block new IPs, unblock with one click

**API Endpoints:**
```
GET  /api/v1/status             Daemon status, uptime, component health
GET  /api/v1/findings           Current active findings
GET  /api/v1/history            Paginated history (?limit=50&offset=0)
GET  /api/v1/quarantine         Quarantined files with metadata
GET  /api/v1/stats              Severity counts and per-check breakdown
GET  /api/v1/blocked-ips        Currently blocked IPs with reason/expiry
GET  /api/v1/health             Daemon health: fanotify status, watchers, uptime
GET  /api/v1/history/csv        Export full history as CSV download
WS   /ws/findings               Real-time finding stream (WebSocket)

POST /api/v1/block-ip           Block an IP {"ip":"...","reason":"..."}
POST /api/v1/unblock-ip         Unblock an IP + flush cphulk {"ip":"..."}
POST /api/v1/dismiss            Dismiss/acknowledge a finding {"key":"check:message"}
POST /api/v1/quarantine-restore Restore quarantined file {"id":"..."}
POST /api/v1/scan-account       Scan single account {"account":"username"}
POST /api/v1/fix                Apply fix for a finding {"check":"...","message":"..."}
POST /api/v1/fix-bulk           Apply fixes to multiple findings [{...}, ...]

GET  /api/v1/firewall/status    Firewall config, set sizes, feature flags
GET  /api/v1/firewall/audit     Firewall audit log (?limit=N)
GET  /api/v1/firewall/subnets   Blocked subnet list
GET  /api/v1/firewall/check     Check if IP is blocked (?ip=X) — CSM + cphulk
POST /api/v1/firewall/unban     Unblock IP from CSM + cphulk {"ip":"..."}
POST /api/v1/firewall/deny-subnet   Block a CIDR range {"cidr":"...","reason":"..."}
POST /api/v1/firewall/remove-subnet Remove subnet block {"cidr":"..."}
POST /api/v1/firewall/flush     Clear all blocked IPs
GET  /api/v1/fix-preview        Preview what a fix would do (?check=...&message=...)
```

**Security:**
- Token auth via Bearer header or HttpOnly/Secure/SameSite=Strict cookie
- CSRF protection on all POST endpoints (HMAC-derived token, validated via X-CSRF-Token header)
- Security headers: X-Frame-Options DENY, CSP, HSTS, X-Content-Type-Options nosniff, X-XSS-Protection, Referrer-Policy
- TLS-only with auto-generated self-signed cert (localhost-bound by default)
- Rate-limited login (5/min per IP, port-stripped)
- Rate-limited account scanning (one concurrent scan at a time)
- IP format validation on block operations (`net.ParseIP`)
- Auto-escaping templates (`html/template`), cookie auth for WebSocket (no token in URL)
- Logout endpoint clears session cookie
- MaxHeaderBytes limit (1MB)

**Architecture:** Two-layer design — the Go binary serves the REST API, WebSocket, and auth (~8MB). The frontend ([Tabler](https://tabler.io) dark theme, MIT-licensed) lives on disk at `/opt/csm/ui/` and is loaded at startup. If the UI directory is missing, the server runs in API-only mode. Auth token never exposed to browser JS — WebSocket uses cookie auth.

## CSM vs Imunify360

| Capability | CSM | Imunify360 |
|---|---|---|
| Real-time file monitoring | fanotify (< 1 sec) | fanotify |
| Malware signatures | 47 rules (YAML + YARA) | Proprietary database (thousands) |
| PHP runtime protection | auto_prepend_file shield | PHP extension (deeper hooks) |
| Brute-force protection | PAM integration + 7 log-based vectors | PAM + gray listing |
| WAF | ModSecurity status/rule monitoring | Full ModSecurity ruleset management |
| Malware cleaning | 7 surgical strategies + DB spam cleaning | Hundreds of cleaning patterns |
| Outbound email scanning | Header + body analysis for phishing/spam | Content scanning + blocking |
| Per-account scan | `csm scan <user>` CLI + Web UI (16 checks, ~5 sec) | Per-account scan from UI |
| Web dashboard | Embedded HTTPS + WebSocket + actions (block/unblock/dismiss/restore/scan) | WHM plugin |
| IP blocking | Native nftables engine (O(1) set lookup) with auto-expiry | CSF + CAPTCHA gray listing |
| fail2ban replacement | All standard jails covered + subnet auto-block + threat feeds | Not applicable |
| cPanel session monitoring | Multi-IP correlation, credential stuffing | Not available |
| Cross-account correlation | Coordinated attack detection | Not available |
| Phishing detection | 8-layer (brand, structural, directory, PHP, iframe, credential logs, ZIPs) | Not available |
| WordPress DB scanning | Post/option injection, rogue admins, spam | Not available |
| Nulled plugin detection | Crack signature scanning | Not available |
| External signature updates | `csm update-rules` + SIGHUP reload | Automatic daily |
| Password hijack detection | Correlates password change + re-login from new IP | Not available |
| Transparency | Full finding details, check names, evidence | Black box |
| Dependencies | 3 (yaml.v3, yara-x, nftables) | Hundreds (Python, ClamAV, etc.) |
| Binary size | ~8 MB static | ~500 MB+ installed |

## Replaces CSF, LFD, fail2ban, and cpanel-service

CSM fully replaces:
- **CSF** (ConfigServer Firewall) — nftables engine with O(1) hash sets, per-IP meters, IPv6, atomic apply
- **LFD** (Login Failure Daemon) — PAM listener + 7 log-based brute force detection vectors, faster than LFD's Perl regex parsing
- **fail2ban** — all standard jails covered: sshd, apache-auth, postfix/dovecot, FTP, WordPress, cPanel. Plus subnet auto-blocking, threat intelligence feeds, and permanent block escalation that fail2ban doesn't have
- **cpanel-service** (IP unblock API) — native `/api/v1/firewall/check` and `/api/v1/firewall/unban` endpoints with Bearer token auth, cphulk integration

## nftables Firewall Engine

CSM includes a native nftables firewall engine that replaces CSF (ConfigServer Firewall). The engine uses the kernel netlink API directly via Go — no iptables, no Perl, no shell commands.

**Implemented:**
- Atomic ruleset application (all-or-nothing via single netlink transaction)
- Named IP sets: `blocked_ips` (with per-element timeout), `allowed_ips`, `infra_ips` (CIDR intervals), `country_blocked`
- SYN flood protection (rate-limited SYN packets before port rules)
- Per-minute new connection rate limiting
- Per-port flood protection (SMTP ports: 40 connections per 300 seconds)
- UDP flood protection (configurable rate/burst)
- Country blocking via CIDR range files
- Outbound SMTP restriction by UID (prevents compromised accounts from spamming)
- Silent drop for scanner-targeted ports (no log noise)
- Deny IP limits (prevents memory exhaustion from runaway blocking)
- Restricted TCP ports (WHM/SSH only accessible from infra IPs)
- INVALID conntrack state drop (malformed packets rejected early)
- Outbound TCP REJECT (sends RST instead of silent DROP for faster failure)
- Subnet/CIDR blocking via `blocked_nets` interval set
- Firewall audit trail (JSONL log of all changes, 10MB rotation)
- Subnet auto-blocking (auto-block /24 when 3+ IPs from same range)
- Dynamic DNS (resolve hostnames to IPs, update allowed set every 5 min)
- Config profiles (save/list/restore firewall configuration snapshots)
- IPv6 dual-stack (separate IPv6 sets for blocked/allowed/infra, dual-stack rule matching)
- Per-IP rate limiting via nftables meters (SYN flood, connection rate, UDP flood)
- Per-IP concurrent connection limit (CONNLIMIT)
- GeoIP auto-update (download country CIDR lists from public source)
- IP geolocation lookup (`csm firewall lookup <ip>` — shows country, block status, infra match)
- Temporary allows with TTL (auto-expire, cleaned every 10 min by daemon)
- Permanent block escalation (auto-promote after N temp blocks within interval — CSF's LF_PERMBLOCK)
- State persistence with atomic writes (survives restart)
- CSF migration tool (`csm firewall migrate-from-csf`)

**Firewall CLI:**
```
csm firewall status                     Show firewall status
csm firewall deny <ip> [reason]         Block an IP permanently
csm firewall allow <ip> [reason]        Add to allowed list
csm firewall remove <ip>                Remove from blocked/allowed
csm firewall grep <pattern>             Search by IP or reason
csm firewall tempban <ip> <dur> [reason] Temporary block (1h, 24h, 7d)
csm firewall tempallow <ip> <dur> [reason] Temporary allow (4h, 1d)
csm firewall ports                      Show port configuration
csm firewall deny-subnet <cidr> [reason] Block a subnet (e.g. 1.2.3.0/24)
csm firewall remove-subnet <cidr>       Remove subnet block
csm firewall deny-file <path>           Bulk block IPs from file
csm firewall allow-file <path>          Bulk allow IPs from file
csm firewall flush                      Clear all dynamic blocks
csm firewall restart                    Reapply full ruleset
csm firewall audit [limit]              View firewall audit log
csm firewall profile save|list|restore  Config profile management
csm firewall update-geoip               Download country IP block lists
csm firewall lookup <ip>                IP geolocation and block status
csm firewall migrate-from-csf [--apply] CSF migration (dry-run default)
```

## Roadmap

### Firewall — Nice-to-have (CSF is fully replaced)
- Port knocking (open SSH port after connection sequence — SSH already behind restricted_tcp)
- Cluster mode (synchronize block lists across multiple servers)
- CloudFlare WAF integration (push blocks to CF firewall)
- Messenger (redirect blocked users to explanation page instead of dropping)

### Web UI — Security Hardening
- ~~Audit log of all UI actions (who blocked/unblocked/dismissed what)~~ Done: `ui_audit.jsonl` + `/api/v1/audit`
- Move inline JavaScript to external files for strict CSP
- CORS/origin validation on API endpoints

### Web UI — Features
- ~~Date range picker on history page~~ Done: from/to date inputs with server-side filtering
- ~~Bulk actions: dismiss multiple findings, restore multiple files, unblock multiple IPs~~ Done: bulk dismiss/fix on findings, bulk unblock on blocked IPs
- Account view page: per-account findings, quarantine, login history
- Rule management: view loaded YAML/YARA rules, trigger reload via UI

### Web UI — UX
- ~~Toast notifications instead of alert() dialogs~~ Done: `CSM.toast()` + `CSM.confirm()` modal
- ~~Dark/light theme toggle~~ Done: localStorage-persisted theme toggle
- ~~Responsive mobile layout~~ Done: Tabler/Bootstrap responsive grid + viewport meta

### Imunify360 Parity
- ~~CAPTCHA/challenge pages instead of hard IP blocks (gray listing)~~ Done: proof-of-work challenge server
- Trusted country IP filtering for cPanel login alerts (reduce false positives)
- Virtual patching — auto-updated WAF rules for new WordPress CVEs

### Platform
- ~~WHM plugin integration for Web UI dashboard~~ Done: CGI redirect plugin
- Binary signing with cosign
- Multi-server config management
