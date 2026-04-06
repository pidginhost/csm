# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-04-06

Initial open-source release.

### Features

- **Real-time file monitor** — fanotify-based detection of webshells and malware in < 1 second
- **Log watchers** — inotify on cPanel, SSH, FTP, Exim, and webmail auth logs (~2s detection)
- **PAM brute-force listener** — real-time blocking on SSH/FTP/cPanel login failures
- **Critical scanner** — 34 checks every 10 minutes (processes, network, auth, reputation)
- **Deep scanner** — 28 checks every 60 minutes (filesystem, WP integrity, phishing, DB)
- **nftables firewall** — kernel netlink API, IP/subnet blocking, rate limiting, country blocking
- **ModSecurity management** — rule deployment, per-domain overrides, escalation control, web UI
- **Signature engine** — YAML + YARA-X dual scanner with hot-reload and auto-fetch from YARA Forge
- **Email AV** — ClamAV + YARA-X scanning of Exim spool and attachments
- **Challenge pages** — SHA-256 proof-of-work for gray-listed IPs (CAPTCHA alternative)
- **Threat intelligence** — AbuseIPDB, GeoIP (MaxMind), attack correlation, IP scoring
- **Performance monitor** — PHP, MySQL, Redis, WordPress, OOM detection
- **Web UI** — 13-page HTTPS dashboard (Tabler CSS) with audit log
- **Alerts** — email, Slack, Discord, generic webhooks
- **Auto-response** — process kill, file quarantine, IP blocking, subnet blocking, permblock escalation, 7 malware remediation strategies
- **PHP runtime shield** — via `auto_prepend_file`
- **WHM plugin** — single-pane-of-glass integration
- **WordPress plugin checker** — outdated plugin detection with WordPress.org API
- **Packaging** — RPM and DEB via nFPM, curl installer, deploy.sh upgrade script

### Security

- Token auth with Bearer header and HttpOnly/Secure/SameSite=Strict cookie
- CSRF protection (HMAC-derived token) on all state-mutating endpoints
- Security headers: X-Frame-Options DENY, CSP, HSTS, X-Content-Type-Options
- TLS-only web UI with auto-generated self-signed certificate
- Rate-limited login (5/min per IP) and API (600/min per IP)
- Infrastructure IP protection: daemon refuses to block infrastructure CIDRs
- Commit-confirmed firewall apply with auto-rollback timer

[Unreleased]: https://github.com/pidginhost/csm/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/pidginhost/csm/releases/tag/v2.0.0
