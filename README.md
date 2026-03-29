# CSM — cPanel Security Monitor

Real-time security monitoring daemon for cPanel/WHM shared hosting servers. A single static Go binary that detects compromises, backdoors, phishing, and suspicious activity — then alerts and responds within seconds.

Designed as a full Imunify360 replacement. Also replaces CSF, LFD, and fail2ban with a native nftables firewall engine.

Built after real incidents where GSocket reverse shells, LEVIATHAN webshell toolkits, credential-stuffed cPanel accounts, and phishing kits were found across production servers.

## Quick Start

```bash
# Install from GitLab Package Registry
GITLAB_TOKEN=xxx /opt/csm/deploy.sh install

# Configure
vi /opt/csm/csm.yaml   # set hostname, alert email, infra IPs

# Validate and baseline
csm validate
csm baseline

# Start
systemctl start csm.service
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
 +-- threat intelligence          IP reputation, attack tracking, auto-blocking
 +-- alert dispatcher             Batching, dedup, rate limiting, auto-response
 +-- web UI                       HTTPS dashboard, findings, firewall, threat intel
```

## Performance

Benchmarked on a production cPanel server (168 accounts, 275 WordPress sites, 28M files):

| Component | Speed | Resources |
|---|---|---|
| fanotify file monitor | < 1 second | < 0.1% CPU, ~5 MB |
| inotify log watchers | ~2 seconds | < 0.1% CPU, ~1 MB |
| Critical checks (30) | Every 10 min, < 1 sec | ~35 MB peak |
| Deep checks (17) | Every 60 min, ~40 sec | ~100 MB peak |
| Daemon idle | — | 45 MB resident |
| Binary size | — | ~8 MB static |

## Detection Coverage

### Real-Time (< 2 seconds)

**File monitor (fanotify):** webshell creation, PHP in uploads/languages/upgrade dirs, executable drops in .config, .htaccess injection, obfuscated PHP analysis, .user.ini tampering, phishing pages, credential harvest logs, phishing kit ZIPs, YAML + YARA signature matching.

**Log watchers (inotify):** cPanel logins from non-infra IPs, password changes, File Manager uploads, SSH logins, FTP logins/failures, exim anomalies, API auth failures, webmail attempts.

**PAM listener:** SSH/FTP/email brute force — blocks IPs within seconds of threshold breach.

### Periodic Critical (30 checks, every 10 min)

Fake kernel threads, suspicious processes, PHP process inspection, shadow/root password changes, UID 0 accounts, SSH keys/config, API tokens, WHM access, cPanel logins with multi-IP correlation, crontab inspection, outbound connections (C2, backdoor ports), DNS tunneling, firewall integrity, mail queue, kernel modules, MySQL superuser audit, database dump detection, paste site exfiltration, WordPress login/xmlrpc brute force, user enumeration, FTP/webmail brute force, self-health.

### Periodic Deep (17 checks, every 60 min)

WordPress core integrity (parallel checksums), nulled plugin detection, RPM binary verification, open_basedir checks, symlink attacks, WAF mode/staleness/bypass, PHP config changes, 8-layer phishing detection, PHP content analysis, signature scanning, WP database injection/siteurl hijacking/rogue admins/spam, outbound email scanning, DNS zone changes, SSL certificate issuance.

### Auto-Response

| Action | Description |
|---|---|
| Kill processes | Fake kernel threads, reverse shells, GSocket (never root/system) |
| Quarantine files | Webshells, backdoors, phishing to `/opt/csm/quarantine/` with metadata |
| Block IPs | Attacker IPs via nftables with configurable expiry |
| Clean malware | 7 strategies: @include, prepend/append, inline eval, base64 chains, chr/pack, hex injection + DB spam |
| PHP shield | Blocks PHP execution from uploads/tmp, detects webshell parameters |
| PAM integration | Real-time login failure blocking |

## Web UI

HTTPS dashboard with real-time monitoring, active findings management, threat intelligence, and firewall control.

### Pages

| Page | Purpose |
|---|---|
| **Dashboard** | 24h stats, timeline chart, live feed, accounts at risk, auto-response summary, top attacked accounts, 30-day trend |
| **Findings** | Active findings with search/filter/group, fix/dismiss/suppress, bulk actions, on-demand account scan |
| **History** | Paginated archive with date/severity filters, CSV export |
| **Quarantine** | Quarantined files with content preview and restore |
| **Firewall** | Config display, blocked IPs/subnets with GeoIP, whitelist management, bulk unblock |
| **Threat Intel** | IP lookup with scoring, top attackers, attack type breakdown, whitelist management |
| **Incidents** | Forensic timeline correlating events by IP or account |
| **Rules** | YAML/YARA rule management, suppression rules, state export/import, test alerts |
| **Audit** | System-wide action log (block, fix, dismiss, whitelist, restore) |

### Security

- Token auth via Bearer header or HttpOnly/Secure/SameSite=Strict cookie
- CSRF protection on all mutations (HMAC-derived token)
- Security headers: X-Frame-Options DENY, CSP, HSTS, nosniff
- TLS-only with auto-generated self-signed cert
- Rate-limited login (5/min per IP) and API (120/min per IP)
- Browser notifications for critical findings

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
  GET  /api/v1/geoip               IP geolocation (?ip=&detail=)
  GET  /api/v1/audit               UI audit log
  GET  /api/v1/finding-detail      Finding detail with action history (?check=&message=)
  GET  /api/v1/export              Export state (suppressions, whitelist)

Threat Intelligence:
  GET  /api/v1/threat/stats        Attack stats, type breakdown, hourly trend
  GET  /api/v1/threat/top-attackers Top attacking IPs with GeoIP (?limit=)
  GET  /api/v1/threat/ip           IP threat lookup (?ip=)
  GET  /api/v1/threat/events       IP event history (?ip=&limit=)
  GET  /api/v1/threat/whitelist    Whitelisted IPs
  GET  /api/v1/incident            Incident timeline (?ip=&account=&hours=)

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

Replaces CSF, LFD, and fail2ban. Uses the kernel netlink API directly — no iptables, no Perl, no shell commands.

- Atomic ruleset application (single netlink transaction)
- Named IP sets with per-element timeouts (blocked, allowed, infra, country)
- SYN flood, UDP flood, per-IP connection rate limiting
- Country blocking via CIDR range files
- Outbound SMTP restriction by UID
- Subnet/CIDR blocking, auto-block /24 when 3+ IPs from same range
- Permanent block escalation after repeated temp blocks
- Dynamic DNS hostname resolution (updated every 5 min)
- IPv6 dual-stack
- Firewall audit trail (JSONL, 10MB rotation)
- State persistence with atomic writes
- CSF migration tool

```bash
csm firewall status                       # Show status
csm firewall deny <ip> [reason]           # Block IP
csm firewall allow <ip> [reason]          # Allow IP
csm firewall tempban <ip> <dur> [reason]  # Temporary block
csm firewall deny-subnet <cidr> [reason]  # Block subnet
csm firewall grep <pattern>              # Search blocks
csm firewall audit [limit]               # View audit log
csm firewall migrate-from-csf [--apply]  # Migrate from CSF
```

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
  max_per_hour: 10

auto_response:
  enabled: false
  kill_processes: false
  quarantine_files: false
  block_ips: false
  block_expiry: "24h"
  netblock: false
  netblock_threshold: 3

firewall:
  enabled: false
  ipv6: false
  conn_rate_limit: 30
  syn_flood_protection: true

webui:
  enabled: true
  listen: "0.0.0.0:9443"
  auth_token: "your-secret-token"

infra_ips:
  - "10.0.0.0/8"

signatures:
  rules_dir: "/opt/csm/rules"
```

## Commands

| Command | Description |
|---|---|
| `csm daemon` | Run as persistent daemon |
| `csm install` | Deploy config, systemd, auditd rules, logrotate |
| `csm uninstall` | Clean removal |
| `csm run` | Run all checks once, send alerts |
| `csm check` | Run all checks, print to stdout |
| `csm scan <user>` | Scan single account (16 checks) |
| `csm clean <path>` | Clean infected PHP file |
| `csm baseline` | Record current state as known-good |
| `csm validate` | Check config |
| `csm verify` | Verify binary and config integrity |
| `csm update-rules` | Download latest signature rules |
| `csm firewall ...` | Firewall management |
| `csm version` | Version and build info |

## Upgrading

```bash
/opt/csm/deploy.sh upgrade
```

Stops daemon, backs up, downloads, verifies checksum, baselines, restarts. Rolls back on failure.

## Development

```bash
make build-linux    # Cross-compile for Linux amd64
make lint           # golangci-lint
make test           # Unit tests
make deploy SERVER=cluster6
```

98 Go files, ~26,600 lines. 34 UI files (JS/HTML/CSS), ~3,800 lines. 3 Go dependencies (yaml.v3, yara-x, google/nftables).

CI/CD: lint, test, build (amd64 + arm64), publish to GitLab Package Registry, release on tag push.

## Roadmap

### Open

- Per-path fanotify alert debounce (prevent duplicate alerts from rapid writes)
- Process info in fanotify alerts (PID, process name, cPanel username)
- Location-based severity escalation (PHP in .ssh/.cpanel/mail dirs)
- In-flight event deduplication (coalesce rapid writes to same file)
- Trusted country filtering for cPanel login alerts
- Virtual patching (auto-updated WAF rules for WordPress CVEs)
- Binary signing with cosign
- Multi-server management (centralized dashboard, block list sync)
