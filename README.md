# CSM - Continuous Security Monitor

[![Coverage](https://pidginhost.github.io/csm/coverage.svg)](https://pidginhost.github.io/csm/coverage.html)

A security daemon for Linux web servers that detects compromise in seconds, responds automatically, and gives operators one place to see what happened.

CSM was originally built for **cPanel/WHM** on CloudLinux/AlmaLinux, where the majority of its checks are tuned for shared hosting attack patterns. It also runs on plain Ubuntu/Debian with Nginx or Apache and on AlmaLinux/Rocky/RHEL with Apache or Nginx. The daemon auto-detects the OS, control panel, and web server at startup and chooses the correct log paths, config locations, and check set.

Shared hosting servers get hit the same ways: stolen credentials, vulnerable plugins, phishing kits, hijacked mailboxes, and backdoors that sit undiscovered until abuse reports arrive. CSM watches for all of it and acts before a small incident becomes a long cleanup.

**[Documentation](https://pidginhost.github.io/csm/)** | **[Installation](docs/src/installation.md)** | **[Configuration](docs/src/configuration.md)**

## Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| cPanel/WHM on AlmaLinux/CloudLinux/Rocky | Primary target | All 62 checks, WHM plugin, Exim mail stack, account enumeration from `/var/cpanel/users` |
| Plain AlmaLinux / Rocky / RHEL 8+ | Supported | Apache or Nginx auto-detected. Generic Linux + web server checks. cPanel-specific checks are skipped cleanly (not partial failures). |
| Plain Ubuntu 20.04+ / Debian 11+ | Supported | Apache or Nginx auto-detected. System integrity via `debsums`/`dpkg --verify` instead of `rpm -V`. |

The `/home/*/public_html` account-scanning checks (WordPress integrity, htaccess tampering, PHP content analysis, phishing kit detection, per-domain brute force) assume a cPanel layout and do not run on plain Linux. Generic checks (filesystem monitoring, firewall management, ModSecurity audit, SSH/PAM brute force, system integrity, kernel module tracking, suspicious process detection, WAF enforcement) run everywhere.

See [detection-critical.md](docs/src/detection-critical.md) and [detection-deep.md](docs/src/detection-deep.md) for per-check platform support.

## Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
vi /opt/csm/csm.yaml
csm validate && csm baseline
systemctl enable --now csm.service
```

Or install the native package:

```bash
# Debian/Ubuntu
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm_VERSION_amd64.deb
sudo dpkg -i csm_VERSION_amd64.deb

# AlmaLinux/Rocky/RHEL/CloudLinux
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm-VERSION-1.x86_64.rpm
sudo dnf install -y ./csm-VERSION-1.x86_64.rpm
```

Web UI at `https://<server>:9443`

## What It Does

**Watches everything in real time** -- fanotify on `/home`, `/tmp`, `/dev/shm` for malicious files; inotify on logs for auth failures, WAF blocks, mail abuse, and suspicious logins; PAM listener for brute force across all services. Log paths are auto-selected per platform (`/var/log/nginx/*`, `/var/log/httpd/*`, `/var/log/apache2/*`, `/var/log/secure` vs `/var/log/auth.log`).

**Catches mail and admin-panel brute force in seconds** -- separate trackers on Exim mainlog (SMTP submission via dovecot SASL) and Dovecot direct (IMAP, POP3, ManageSieve), each emitting per-IP, per-/24, and per-mailbox signals. The mail tracker also fires `mail_account_compromised` the moment a successful login arrives from an IP that was just failing auth against the same mailbox. Web-side, the access-log watcher counts repeated POSTs to phpMyAdmin and Joomla login endpoints and auto-blocks the source IP.

**Runs up to 62 security checks** -- 34 critical checks every 10 minutes (processes, auth, network, integrity) and 28 deep checks every hour (filesystem, WordPress, phishing, DNS/SSL, mail, database). On non-cPanel hosts the account/mail/WordPress/cPanel-API checks are skipped cleanly so the check set matches the platform's actual attack surface.

**Responds automatically** -- blocks IPs, quarantines files, kills reverse shells, cleans infected PHP, promotes repeat offenders to permanent bans, and routes suspicious traffic through proof-of-work challenges.

**Manages your firewall** -- nftables IP/subnet blocking, temp bans, country blocks, port allowlists, GeoIP decisions, and full audit trail. Works on any modern Linux distro with nftables (Ubuntu 20.04+, Debian 11+, RHEL/Alma/Rocky 8+).

**Covers email abuse** (cPanel only) -- Exim spool AV scanning, attachment quarantine, queue monitoring, weak password audits, external forwarder checks, and DKIM/SPF failure alerting.

**Manages ModSecurity** -- detects ModSec on Apache (`/etc/apache2`, `/etc/httpd`, cPanel EA4) and Nginx (`/etc/nginx/modsec`), scans the correct rule directories, reports stale rules, and emits platform-specific install hints (`apt install libnginx-mod-http-modsecurity`, `dnf install --enablerepo=epel mod_security`, or WHM on cPanel).

**Verifies system integrity** -- `rpm -V` on RHEL family, `debsums` / `dpkg --verify` on Debian/Ubuntu. Same scope of critical binaries on both.

**Includes threat intelligence** -- AbuseIPDB lookups, GeoIP/ASN enrichment, attacker scoring, attack correlation, and bulk IP actions.

Plus: YARA-X scanning, server hardening audits, performance monitoring (PHP/MySQL/Redis/WordPress), and signature-based detection.

## Web UI

14 authenticated pages covering dashboard, findings, quarantine, firewall, ModSecurity, ModSec Rules, threat intel, email, performance, hardening, incidents, rules, audit, and account views. Also available as a WHM plugin.

The dashboard shows 24h stats, a timeline, live event feed, at-risk accounts, and response summary. Key investigation pages support filtering, bulk actions, and drill-down workflows.

## CLI

```
csm daemon              # run the daemon
csm check               # run all checks once
csm status              # show current findings
csm baseline            # set clean-state baseline
csm scan <user>         # scan a specific account
csm firewall ...        # manage firewall rules
csm clean <path>        # clean infected files
csm update-rules        # update detection signatures
csm validate            # validate config
csm verify              # verify binary integrity
```

## Performance

| Component | Speed | Memory |
|-----------|-------|--------|
| fanotify scan | < 1 sec | ~5 MB |
| 34 critical checks | < 1 sec | ~35 MB peak |
| 28 deep checks | ~40 sec | ~100 MB peak |
| Daemon idle | -- | 45 MB resident |

Single Go binary. Optional integrations include YARA-X support, email AV tooling, and MaxMind GeoIP data.

## Development

```bash
go build ./cmd/csm/                    # standard build
go build -tags yara ./cmd/csm/         # with YARA-X support
go test ./... -count=1                 # run tests
go test -race -short ./...             # CI-style test run
make lint                              # lint using repo-local caches
```

Public release artifacts are published on GitHub Releases. The GitLab pipeline remains the internal build and packaging system, but the GitHub repository is the public source of truth for releases, install script downloads, and docs.

## Docs

- [Installation](docs/src/installation.md)
- [Configuration](docs/src/configuration.md)
- [CLI Commands](docs/src/cli.md)
- [Real-Time Detection](docs/src/detection-realtime.md)
- [Critical Checks](docs/src/detection-critical.md)
- [Deep Checks](docs/src/detection-deep.md)
- [Web UI](docs/src/webui.md)

## License

MIT. See [LICENSE](LICENSE). Also see [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).
