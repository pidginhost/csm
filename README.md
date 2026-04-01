# CSM — cPanel Security Monitor

Real-time security monitoring daemon for cPanel/WHM shared hosting servers. A single static Go binary that detects compromises, backdoors, phishing, and suspicious activity — then alerts and responds within seconds.

Designed as a full Imunify360 replacement. Also replaces CSF, LFD, and fail2ban with a native nftables firewall engine.

Built after real incidents where GSocket reverse shells, LEVIATHAN webshell toolkits, credential-stuffed cPanel accounts, and phishing kits were found across production servers.

## Quick Start

### Option 1: Curl installer (interactive)

```bash
curl -sSL https://get.pidginhost.com/csm | bash -s -- --token YOUR_DEPLOY_TOKEN
```

Auto-detects hostname, email, generates WebUI auth token. Prompts for confirmation.

Non-interactive: `bash install.sh --token TOKEN --email admin@example.com --non-interactive`

### Option 2: RPM (CentOS/AlmaLinux/CloudLinux)

```bash
rpm -i csm-VERSION-1.x86_64.rpm
vi /opt/csm/csm.yaml       # review auto-detected config
csm baseline
systemctl enable --now csm.service
```

### Option 3: DEB (Ubuntu/Debian)

```bash
dpkg -i csm_VERSION_amd64.deb
vi /opt/csm/csm.yaml
csm baseline
systemctl enable --now csm.service
```

### Option 4: Manual (deploy.sh)

```bash
GITLAB_TOKEN=xxx /opt/csm/deploy.sh install
vi /opt/csm/csm.yaml   # set hostname, alert email, infra IPs
csm validate
csm baseline
systemctl enable --now csm.service
```

Web UI: `https://<server>:9443/login`

## Architecture

```
csm daemon
 |
 +-- fanotify file monitor        < 1 sec detection on /home, /tmp, /dev/shm
 +-- inotify log watchers         ~2 sec detection on session, access, secure, exim, ftp
 +-- PAM brute-force listener     Real-time login failure tracking
 +-- PHP runtime shield           auto_prepend_file protection
 +-- periodic critical scanner    Every 10 min (processes, network, tokens, firewall)
 +-- periodic deep scanner        Every 60 min (WP integrity, RPM, DB injection, phishing)
 +-- nftables firewall engine     Replaces CSF/LFD/fail2ban
 +-- threat intelligence          IP reputation, attack tracking, GeoIP enrichment
 +-- attack database              Real-time tracking, scoring, correlation
 +-- alert dispatcher             Batching, dedup, rate limiting, auto-response
 +-- web UI                       HTTPS dashboard, findings, firewall, threat intel
 +-- GeoIP auto-updater           MaxMind GeoLite2 City + ASN (24h update cycle)
 +-- email AV orchestrator        ClamAV + YARA-X scanning on Exim spool
 +-- challenge server             Proof-of-work challenge pages for suspicious IPs
```

## Performance

Benchmarked on a production cPanel server (168 accounts, 275 WordPress sites, 28M files):

| Component | Speed | Resources |
|---|---|---|
| fanotify file monitor | < 1 second | < 0.1% CPU, ~5 MB |
| inotify log watchers | ~2 seconds | < 0.1% CPU, ~1 MB |
| Critical checks (31) | Every 10 min, < 1 sec | ~35 MB peak |
| Deep checks (18) | Every 60 min, ~40 sec | ~100 MB peak |
| Daemon idle | — | 45 MB resident |
| Binary size | — | ~8 MB static |

## Detection Coverage

### Real-Time (< 2 seconds)

**File monitor (fanotify):** webshell creation, PHP in uploads/languages/upgrade dirs, PHP in .ssh/.cpanel/mail dirs (critical escalation), executable drops in .config, .htaccess injection, obfuscated PHP analysis, .user.ini tampering, phishing pages, credential harvest logs, phishing kit ZIPs, YAML + YARA signature matching (PHP, HTML, .htaccess, .user.ini), per-path alert deduplication (30s cooldown), process info enrichment (PID/command/UID).

**Log watchers (inotify):** cPanel logins from non-infra IPs (with trusted country filtering), password changes, File Manager uploads, SSH logins, FTP logins/failures, exim anomalies, API auth failures, webmail attempts.

**PAM listener:** SSH/FTP/email brute force — blocks IPs within seconds of threshold breach.

### Periodic Critical (31 checks, every 10 min)

Fake kernel threads, suspicious processes, PHP process inspection, shadow/root password changes, UID 0 accounts, SSH keys/config, SSHD config audit, SSH login analysis, API tokens, WHM access, cPanel logins with multi-IP correlation, cPanel File Manager uploads, crontab inspection, outbound connections (C2, backdoor ports), per-user outbound connections, DNS tunneling, firewall integrity, mail queue, per-account mail volume, kernel modules, MySQL superuser audit, database dump detection, paste site exfiltration, WordPress login/xmlrpc brute force, FTP logins/failures, webmail brute force, API auth failures, IP reputation scoring, local threat scoring, ModSecurity audit log, self-health.

### Periodic Deep (18 checks, every 60 min)

Filesystem scanning, webshell detection, .htaccess injection scanning, WordPress core integrity (parallel checksums), file baseline changes, PHP content analysis, 8-layer phishing detection, nulled plugin detection, RPM binary verification, group-writable PHP audit, open_basedir checks, symlink attacks, PHP config changes, DNS zone changes, SSL certificate issuance, WAF mode/staleness/bypass, WP database injection/siteurl hijacking/rogue admins/spam, outbound email scanning.

### Auto-Response

| Action | Description |
|---|---|
| Kill processes | Fake kernel threads, reverse shells, GSocket (never root/system) |
| Quarantine files | Webshells, backdoors, phishing to `/opt/csm/quarantine/` with metadata; realtime signature matches auto-quarantined when high-confidence (category + entropy validation) |
| Block IPs | Attacker IPs via nftables with configurable expiry |
| Clean malware | 7 strategies: @include, prepend/append, inline eval, base64 chains, chr/pack, hex injection + DB spam |
| PHP shield | Blocks PHP execution from uploads/tmp, detects webshell parameters |
| PAM integration | Real-time login failure blocking |
| Subnet blocking | Auto-block /24 when 3+ IPs from same range |
| Permblock escalation | Auto-promote to permanent after repeated temp blocks |

## Web UI

HTTPS dashboard with polling-based live updates (10s feed, 30s stats). Dark/light theme.

### Pages

| Page | Purpose |
|---|---|
| **Dashboard** | 24h stats, timeline chart, live feed, accounts at risk, auto-response summary, top attacked accounts, attack types |
| **Findings** | Active findings with search/filter/group, fix/dismiss/suppress, bulk actions, on-demand account scan |
| **History** | Paginated archive with date/severity filters, CSV export |
| **Quarantine** | Quarantined files with content preview and restore |
| **Firewall** | Config display, blocked IPs/subnets with GeoIP, whitelist management, search, audit log |
| **Threat Intel** | IP lookup with scoring/GeoIP/ASN, top attackers, attack type breakdown, hourly trend, whitelist management |
| **Incidents** | Forensic timeline correlating events by IP or account |
| **Rules** | YAML/YARA rule management, suppression rules, state export/import, test alerts |
| **Audit** | System-wide action log (block, fix, dismiss, whitelist, restore) |
| **Account** | Per-account security view with findings, quarantine, and history |
| **Email** | Email security dashboard and statistics |

### Security

- Token auth via Bearer header or HttpOnly/Secure/SameSite=Strict cookie
- CSRF protection on all mutations (HMAC-derived token)
- Security headers: X-Frame-Options DENY, CSP, HSTS, nosniff
- TLS-only with auto-generated self-signed cert
- Rate-limited login (5/min per IP) and API (600/min per IP)
- Bearer auth skips CSRF (API-to-API calls)

### API

```
Status & Data:
  GET  /api/v1/status              Daemon status, uptime, scan state
  GET  /api/v1/findings            Current active findings
  GET  /api/v1/history             Paginated history (?limit=&offset=&from=&to=&severity=)
  GET  /api/v1/stats               24h severity counts, accounts at risk, auto-response summary
  GET  /api/v1/stats/trend         30-day daily severity counts
  GET  /api/v1/quarantine          Quarantined files with metadata
  GET  /api/v1/quarantine-preview  Preview quarantined file content (?id=)
  GET  /api/v1/blocked-ips         Blocked IPs with reason/expiry
  GET  /api/v1/accounts            cPanel account list
  GET  /api/v1/account             Per-account findings/quarantine/history (?name=)
  GET  /api/v1/health              Daemon health
  GET  /api/v1/history/csv         CSV export
  GET  /api/v1/audit               UI audit log
  GET  /api/v1/finding-detail      Finding detail with action history (?check=&message=)
  GET  /api/v1/export              Export state (suppressions, whitelist)
  GET  /api/v1/incident            Incident timeline (?ip=&account=&hours=)
  GET  /api/v1/email/stats         Email security statistics
  GET  /api/v1/email/quarantine    Quarantined email list
  GET  /api/v1/email/av/status     Email AV watcher status

GeoIP:
  GET  /api/v1/geoip               IP geolocation (?ip=&detail=1)
  POST /api/v1/geoip/batch         Batch GeoIP lookup (CSRF required)

Threat Intelligence:
  GET  /api/v1/threat/stats        Attack stats, type breakdown, hourly trend
  GET  /api/v1/threat/top-attackers Top attacking IPs with GeoIP (?limit=)
  GET  /api/v1/threat/ip           IP threat lookup (?ip=)
  GET  /api/v1/threat/events       IP event history (?ip=&limit=)
  GET  /api/v1/threat/whitelist    Whitelisted IPs
  GET  /api/v1/threat/db-stats     Attack database statistics
  POST /api/v1/threat/block-ip           Block IP via threat intel

Firewall:
  GET  /api/v1/firewall/status     Config, blocked/allowed counts
  GET  /api/v1/firewall/subnets    Blocked subnets
  GET  /api/v1/firewall/audit      Firewall audit log
  GET  /api/v1/firewall/check      Check if IP is blocked (?ip=)

Rules:
  GET  /api/v1/rules/status        YAML/YARA rule counts, version
  GET  /api/v1/rules/list          Rule files
  GET  /api/v1/suppressions        Suppression rules

Actions (POST, CSRF required):
  POST /api/v1/fix                 Apply fix for a finding
  POST /api/v1/fix-bulk            Bulk fix multiple findings
  POST /api/v1/dismiss             Dismiss a finding
  POST /api/v1/scan-account        On-demand account scan
  POST /api/v1/block-ip            Block an IP
  POST /api/v1/unblock-ip          Unblock an IP
  POST /api/v1/unblock-bulk        Bulk unblock IPs
  POST /api/v1/quarantine-restore  Restore quarantined file
  POST /api/v1/email/quarantine/   Email quarantine actions (release/delete)
  POST /api/v1/test-alert          Send test alert through all channels
  POST /api/v1/import              Import state bundle
  POST /api/v1/threat/whitelist-ip       Permanent whitelist
  POST /api/v1/threat/temp-whitelist-ip  Temporary whitelist
  POST /api/v1/threat/clear-ip           Unblock and clear
  POST /api/v1/threat/unwhitelist-ip     Remove from whitelist
  POST /api/v1/firewall/deny-subnet      Block subnet
  POST /api/v1/firewall/remove-subnet   Remove subnet block
  POST /api/v1/firewall/flush            Clear all blocks
  POST /api/v1/firewall/unban            Unblock IP from firewall + cphulk
  POST /api/v1/rules/reload              Reload signature rules
  POST /api/v1/suppressions              Add/delete suppression rules
```

## nftables Firewall Engine

Replaces CSF, LFD, and fail2ban. Uses the kernel netlink API directly via `google/nftables` — no iptables, no Perl, no shell commands.

- Atomic ruleset application (single netlink transaction)
- Named IP sets with per-element timeouts (blocked, allowed, infra, country)
- SYN flood, UDP flood, per-IP connection rate limiting, per-port flood limiting
- Country blocking via MaxMind GeoIP CIDR ranges
- Outbound SMTP restriction by UID
- Subnet/CIDR blocking, auto-block /24 when 3+ IPs from same range
- Permanent block escalation after repeated temp blocks
- Dynamic DNS hostname resolution (updated every 5 min)
- IPv6 dual-stack with separate sets
- Commit-confirmed safety (Juniper-style auto-rollback timer)
- Infra IP protection (refuses to block infrastructure IPs)
- Firewall audit trail (JSONL, 10MB rotation)
- State persistence with atomic writes
- CSF migration tool with per-IP:port allow support
- cphulk integration (unblock flushes cphulk too)

```bash
csm firewall status                              # Show status and statistics
csm firewall deny <ip> [reason]                  # Block IP permanently
csm firewall allow <ip> [reason]                 # Allow IP (all ports)
csm firewall allow-port <ip> <port> [reason]     # Allow IP on specific port
csm firewall remove-port <ip> <port>             # Remove port-specific allow
csm firewall remove <ip>                         # Remove from blocked and allowed
csm firewall grep <pattern>                      # Search blocked/allowed IPs
csm firewall tempban <ip> <dur> [reason]         # Temporary block
csm firewall tempallow <ip> <dur> [reason]       # Temporary allow
csm firewall deny-subnet <cidr> [reason]         # Block subnet
csm firewall remove-subnet <cidr>               # Remove subnet block
csm firewall ports                               # Show configured port rules
csm firewall deny-file <path>                    # Bulk block from file
csm firewall allow-file <path>                   # Bulk allow from file
csm firewall flush                               # Clear all dynamic blocks
csm firewall restart                             # Reapply full ruleset
csm firewall apply-confirmed <minutes>           # Apply with auto-rollback timer
csm firewall confirm                             # Confirm applied changes
csm firewall migrate-from-csf [--apply]          # Migrate from CSF
csm firewall profile save|list|restore <name>    # Profile management
csm firewall audit [limit]                       # View audit log
csm firewall update-geoip                        # Download country IP blocks
csm firewall lookup <ip>                         # GeoIP + block status lookup
```

## GeoIP

MaxMind GeoLite2 integration for IP geolocation and ASN enrichment.

- Auto-downloads City + ASN databases on first use
- Auto-updates every 24 hours (configurable)
- Used in: threat intel page, top attackers, IP lookup, firewall audit
- RDAP fallback for ISP/org details (24h cache)

```yaml
geoip:
  account_id: "YOUR_MAXMIND_ACCOUNT_ID"
  license_key: "YOUR_MAXMIND_LICENSE_KEY"
  editions:
    - GeoLite2-City
    - GeoLite2-ASN
  auto_update: true
  update_interval: 24h
```

Free account: https://www.maxmind.com/en/geolite2/signup

## Signature Rules

YAML and YARA-X rules in `/opt/csm/rules/`, scanned in real-time via fanotify and during deep scans.

```yaml
rules:
  - name: webshell_c99
    severity: critical
    category: webshell
    file_types: [".php"]
    patterns: ["c99shell", "c99_buff_prepare"]
    min_match: 1
```

Update rules: `csm update-rules` + `kill -HUP $(pidof csm)` to reload without restart.

YARA-X (optional): build with `go build -tags yara ./cmd/csm`. Place `.yar` files alongside YAML rules.

## Configuration

```yaml
# /opt/csm/csm.yaml
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
    type: "slack"   # slack, discord, generic
  heartbeat:
    enabled: false
    url: ""         # healthchecks.io, cronitor, dead man's switch
  max_per_hour: 10

webui:
  enabled: true
  listen: "0.0.0.0:9443"
  auth_token: "your-secret-token"  # auto-generated on package install

auto_response:
  enabled: false
  kill_processes: false
  quarantine_files: false
  block_ips: false
  block_expiry: "24h"
  netblock: false
  netblock_threshold: 3
  permblock: false
  permblock_count: 4

firewall:
  enabled: false
  ipv6: false
  conn_rate_limit: 30       # new connections per minute per IP
  syn_flood_protection: true
  conn_limit: 50            # max concurrent connections per IP
  smtp_block: false         # restrict outbound SMTP to allowed users
  log_dropped: true

geoip:
  account_id: ""
  license_key: ""

infra_ips: []               # YOUR management/monitoring network CIDRs

suppressions:
  trusted_countries: ["US", "RO"]   # suppress cPanel login alerts from these
  upcp_window_start: "00:30"        # cPanel nightly update window
  upcp_window_end: "02:00"

signatures:
  rules_dir: "/opt/csm/rules"
```

## Commands

| Command | Description |
|---|---|
| `csm daemon` | Run as persistent daemon |
| `csm install` | Deploy config, systemd, auditd rules, logrotate, WHM plugin |
| `csm uninstall` | Clean removal |
| `csm run` | Run all checks once, send alerts |
| `csm check` | Run all checks, print to stdout (no alerts) |
| `csm check-critical` | Test critical checks only (no alerts) |
| `csm check-deep` | Test deep checks only (no alerts) |
| `csm run-critical` | Run critical checks only (used by systemd timer) |
| `csm run-deep` | Run deep scan only (used by systemd timer) |
| `csm status` | Show current state, last run, active findings |
| `csm scan <user>` | Scan single account (16 checks) |
| `csm clean <path>` | Clean infected PHP file |
| `csm baseline` | Record current state as known-good |
| `csm rehash` | Update binary/config hashes without scanning |
| `csm validate` | Validate config with structured output |
| `csm validate --deep` | Validate config with connectivity probes |
| `csm config show` | Display config with secrets redacted |
| `csm verify` | Verify binary and config integrity |
| `csm update-rules` | Download latest signature rules |
| `csm update-geoip` | Update MaxMind GeoLite2 databases |
| `csm enable --php-shield` | Enable PHP runtime protection |
| `csm disable --php-shield` | Disable PHP runtime protection |
| `csm firewall ...` | Firewall management (23 subcommands) |
| `csm version` | Version and build info |

## Installation Methods

| Method | Command | Best for |
|---|---|---|
| Curl installer | `curl -sSL .../install.sh \| bash -s -- --token TOKEN` | Quick trial, first install |
| RPM | `rpm -i csm-VERSION.x86_64.rpm` | CentOS/AlmaLinux/CloudLinux production |
| DEB | `dpkg -i csm_VERSION_amd64.deb` | Ubuntu/Debian production |
| deploy.sh | `/opt/csm/deploy.sh install` | Existing deploy token setup |

All methods produce the same installed state. RPM/DEB auto-detect hostname and email, generate auth token.

## Upgrading

```bash
/opt/csm/deploy.sh upgrade
```

Stops daemon, backs up binary, downloads new version, verifies SHA256 checksum, extracts UI assets and rules, rehashes config, restarts daemon. Rolls back on failure.

RPM/DEB: `yum update csm` / `dpkg -i csm_NEW.deb` — handles stop/start automatically.

## Development

```bash
make build-linux    # Cross-compile for Linux amd64
make lint           # golangci-lint
make test           # Unit tests
make deploy SERVER=cluster6
```

CI/CD: lint, vet, test, build (amd64 + arm64), package (RPM + DEB via nFPM), publish to GitLab Package Registry, cleanup old packages, release on tag push.

## Roadmap

### Open

- Binary signing with cosign
- Multi-server management (centralized dashboard, block list sync)
- YUM/APT repository hosting for automated updates
- `csm backup` / `csm restore` for state portability
