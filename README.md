# CSM — Continuous Security Monitor

[![Coverage](https://pidginhost.github.io/csm/coverage.svg)](https://pidginhost.github.io/csm/coverage.html)
[![Go Report Card](https://goreportcard.com/badge/github.com/pidginhost/csm)](https://goreportcard.com/report/github.com/pidginhost/csm)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pidginhost/csm/badge)](https://scorecard.dev/viewer/?uri=github.com/pidginhost/csm)
[![Go Reference](https://pkg.go.dev/badge/github.com/pidginhost/csm.svg)](https://pkg.go.dev/github.com/pidginhost/csm)
[![Release](https://img.shields.io/github/v/release/pidginhost/csm?sort=semver)](https://github.com/pidginhost/csm/releases)
[![License: MIT](https://img.shields.io/github/license/pidginhost/csm)](LICENSE)

A security daemon for Linux web servers that detects compromise in seconds, responds automatically, and gives operators one place to see what happened. Purpose-built for shared hosting attack patterns — stolen credentials, vulnerable plugins, phishing kits, hijacked mailboxes, backdoors — with first-class support for **cPanel/WHM** and clean fallback on plain Ubuntu/Debian and AlmaLinux/Rocky/RHEL with Apache or Nginx.

**[Documentation](https://pidginhost.github.io/csm/)** • **[Installation](docs/src/installation.md)** • **[Configuration](docs/src/configuration.md)** • **[CLI](docs/src/cli.md)** • **[Web UI](docs/src/webui.md)**

---

## Features

### Real-Time Threat Detection

- **Kernel-level file watcher** — fanotify on `/home`, `/tmp`, `/dev/shm` flags webshells, PHP drops in uploads/.ssh/mail dirs, `.htaccess`/`.user.ini` tampering, and executable drops in under a second.
- **Evasion-aware scanners** — detects obfuscated PHP, fragmented `base64_decode` names, hundreds-of-line concat payloads, and tail-appended code beyond the 32 KB head window of large legitimate files.
- **Non-PHP backdoors** — catches Perl/Python/Bash/Ruby CGI scripts in web directories (e.g. the LEVIATHAN toolkit).
- **Log tailers** — inotify on auth, access, mail, WAF, and cPanel session logs with paths auto-selected per platform.
- **PAM listener** — brute force detection across every PAM service, not just SSH.

### Malware Scanning & Cleanup

- **YARA-X engine** — modern rust-based YARA replacement (VirusTotal yara-x) built in with `-tags yara`.
- **Signature rules** — curated YAML signatures for PHP, HTML, `.htaccess`, `.user.ini`, phishing kits, SEO spam.
- **7 cleaning strategies** — `@include` removal, prepend/append stripping, inline-eval removal, base64 chain decode, chr/pack cleanup, hex injection removal, DB spam cleanup.
- **WordPress integrity** — official checksum verification against `api.wordpress.org`; flags tampered core files.
- **Quarantine with metadata** — owner, permissions, mtime preserved; restoreable from the web UI.
- **High-confidence auto-quarantine** — category match plus entropy ≥ 4.8 or hex density > 20 % to keep legitimate plugins safe.

### Web Application Firewall Management

- **ModSecurity discovery** — detects ModSec on Apache (`/etc/apache2`, `/etc/httpd`, cPanel EA4) and Nginx (`/etc/nginx/modsec`), scans the correct rule dirs, reports stale rules.
- **Rule management UI** — enable/disable rules, edit, reload, and escalate repeat offenders.
- **Install hints per platform** — `apt install libnginx-mod-http-modsecurity`, `dnf install --enablerepo=epel mod_security`, or WHM on cPanel.
- **WAF block correlation** — ModSec denies feed into the attacker scoring and auto-response pipeline.

### Brute-Force & Bad-Bot Protection

- **SMTP brute force** — Exim mainlog tailer emits per-IP, per-/24 subnet, and per-mailbox signals; the per-IP and subnet variants auto-block via nftables.
- **Mail account compromise** — fires the instant a successful login arrives from an IP that was just failing auth against the same mailbox.
- **Dovecot IMAP/POP3/ManageSieve** — direct-auth brute force with matching per-IP/subnet/account signals.
- **WordPress brute force** — real-time access log monitoring for `wp-login.php` and `xmlrpc.php` floods; blocks within seconds.
- **Admin-panel brute force** — tight path matcher for phpMyAdmin and Joomla `/administrator/index.php` to avoid false positives on shared hosting.
- **SSH/PAM, FTP, cPanel login** — tracked through the same scoring and auto-block pipeline.
- **Proof-of-work challenge** — SHA-256 JS challenge with HMAC-verified tokens for suspicious-but-not-confirmed traffic; confirmed malware is always hard-blocked.

### Firewall & Network Protection

- **nftables management** — IP and subnet blocking, temp bans with expiry, permanent bans via escalation, port allowlists, full audit trail.
- **Subnet escalation** — auto-blocks a /24 when 3+ IPs from the same range attack.
- **Permanent-block promotion** — temp bans graduate to permanent after N repeated offenses.
- **Country blocks & GeoIP** — MaxMind-backed decisions, trusted-country allowlist for login alerts.
- **Cloud-relay abuse detector** — scans Exim logs for GCP/AWS/Azure outbound relay patterns and blocks the originating IP ranges.
- **Rate limiting** — 50 blocks/hour cap prevents runaway blocking.

### Email Security *(cPanel)*

- Exim spool AV scanning with attachment quarantine.
- Mail queue monitoring and spamming-script detection.
- Weak-password audits and external forwarder checks.
- DKIM/SPF failure alerting.
- Cloud-relay (GCP/AWS/Azure) outbound abuse detection with retro-scan on startup.

### Account & Content Integrity *(cPanel)*

- `/home/*/public_html` scanning: WordPress integrity, `.htaccess` tampering, PHP content analysis, phishing-kit detection, per-domain brute-force tracking.
- PHP-in-uploads shield — blocks execution from `uploads/`, `tmp/`, and detects webshell parameters.
- Database scanner — flags injected admin users and spam rows in WordPress DBs.

### System Hardening & Integrity

- **Package verification** — `rpm -V` on RHEL family, `debsums` / `dpkg --verify` on Debian/Ubuntu, same critical-binary scope on both.
- **Hardening audits** — SSH config, sysctl, kernel modules, world-writable paths, SUID inventory, outdated packages.
- **Kernel module tracking** — flags new or unexpected modules.
- **Performance checks** — PHP/MySQL/Redis/WordPress health signals that often indicate compromise.

### Automated Response

Block IPs, quarantine files, kill reverse shells and fake kernel threads, clean infected PHP, promote repeat offenders to permanent bans, and route gray-listed traffic through proof-of-work challenges. Never touches root or system processes; infrastructure IPs are never blocked.

### Threat Intelligence

AbuseIPDB lookups, GeoIP/ASN enrichment, attacker scoring, cross-signal correlation, and bulk IP actions from the web UI.

### Web UI & CLI

- **15 authenticated pages** — dashboard, findings, quarantine, firewall, ModSecurity, ModSec Rules, threat intel, email, performance, hardening, incidents, rules, audit, accounts, settings. Also shipped as a **WHM plugin**.
- **Dashboard at a glance** — 24 h stats, timeline, live event feed, at-risk accounts, response summary.
- **Full-featured CLI** — daemon, one-shot check, baseline, per-account scan, firewall, clean, signature update, validate, verify.

### Deployment

- Single static Go binary.
- Native `.deb` and `.rpm` packages, signed releases, and reproducible builds.
- Auto-detects OS, control panel, and web server at startup — no hand-written path configuration.

---

## Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| cPanel/WHM on AlmaLinux / CloudLinux / Rocky | Primary | All 62 checks, WHM plugin, Exim stack, account enumeration from `/var/cpanel/users`. |
| AlmaLinux / Rocky / RHEL 8+ *(plain)* | Supported | Apache or Nginx auto-detected. cPanel-specific checks are skipped cleanly. |
| Ubuntu 20.04+ / Debian 11+ *(plain)* | Supported | Apache or Nginx auto-detected. Integrity via `debsums` / `dpkg --verify`. |

Account-scanning checks (WordPress, `.htaccess`, PHP content, phishing kits, per-domain brute force) assume a cPanel layout. Generic checks — filesystem, firewall, ModSec audit, SSH/PAM brute force, system integrity, kernel modules, suspicious processes, WAF — run everywhere.

See [detection-critical.md](docs/src/detection-critical.md) and [detection-deep.md](docs/src/detection-deep.md) for per-check platform support.

## Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
vi /opt/csm/csm.yaml
csm validate && csm baseline
systemctl enable --now csm.service
```

Native packages:

```bash
# Debian / Ubuntu
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm_VERSION_amd64.deb
sudo dpkg -i csm_VERSION_amd64.deb

# AlmaLinux / Rocky / RHEL / CloudLinux
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm-VERSION-1.x86_64.rpm
sudo dnf install -y ./csm-VERSION-1.x86_64.rpm
```

Web UI at `https://<server>:9443`.

## CLI

```
csm daemon              run the daemon
csm check               run all checks once
csm status              show current findings
csm baseline            set clean-state baseline
csm scan <user>         scan a specific account
csm firewall ...        manage firewall rules
csm clean <path>        clean infected files
csm update-rules        update detection signatures
csm validate            validate config
csm verify              verify binary integrity
```

## Performance

| Component | Speed | Memory |
|-----------|-------|--------|
| fanotify scan | < 1 s | ~5 MB |
| 34 critical checks | < 1 s | ~35 MB peak |
| 28 deep checks | ~40 s | ~100 MB peak |
| Daemon idle | — | 45 MB resident |

Optional: YARA-X (`-tags yara`), email AV tooling, MaxMind GeoIP data.

## Development

```bash
go build ./cmd/csm/                    # standard build
go build -tags yara ./cmd/csm/         # with YARA-X
go test ./... -count=1                 # run tests
go test -race -short ./...             # CI-style run
make lint                              # lint with repo-local caches
```

Public releases live on GitHub; the GitLab pipeline is the internal build and packaging system.

## Docs

- [Installation](docs/src/installation.md)
- [Configuration](docs/src/configuration.md)
- [CLI Commands](docs/src/cli.md)
- [Real-Time Detection](docs/src/detection-realtime.md)
- [Critical Checks](docs/src/detection-critical.md)
- [Deep Checks](docs/src/detection-deep.md)
- [Auto-Response](docs/src/auto-response.md)
- [Challenge Pages](docs/src/challenge.md)
- [ModSecurity](docs/src/modsecurity.md)
- [Firewall](docs/src/firewall.md)
- [Email AV](docs/src/email-av.md)
- [Threat Intel](docs/src/threat-intel.md)
- [Web UI](docs/src/webui.md)

## License

MIT — see [LICENSE](LICENSE). Also [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).
