# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.1] - 2026-04-08

### Fixed

- **Legitimate WordPress users blocked** — `/wp-json/wp/v2/users/me` (admin self-check by Gutenberg/Elementor) matched user enumeration detection. Fixed with URI `$` anchor in ModSec rule 900112 and brute force scanner.
- **28+ plugin files quarantined (GitHub URL FP)** — plugins referencing `raw.githubusercontent.com` for update checks flagged as droppers. GitHub URLs now only flag with dangerous function calls on same line.
- **LiteSpeed Cache plugin quarantined** — `webshell_litespeed_backdoor` matched "litespeed"+"lscache" without exploit regex. Added `require_regex`.
- **Divi theme files quarantined** — `exploit_timthumb` YARA matched "timthumb" in comments. Now requires vulnerable function signatures.
- **Contact forms flagged** — `mailer_forged_headers` matched `mail()` + `From:` + `$_POST` co-presence. Now requires same line.
- **WP core files quarantined** — `dropper_wp_plugin_installer`, `backdoor_wp_muplugin`, `exploit_wp_options_inject`, `exploit_wp_fake_plugin_installer` tightened with structural nesting.
- **wp-config.php flagged** — `wp_db_credential_dump` triggered on the file itself. Added `require_regex` for file-reading functions.
- **Wordfence WAF quarantined** — `backdoor_htaccess_auto_prepend` YARA now excludes WAF plugins.
- **ZIP library quarantined** — `webshell_hex_function_name` matched hex ZIP magic bytes. Now requires hex variable to be called as function.
- **xmlrpc.php quarantined** — `dropper_php_input_stream` triggered on `php://input` alone. Now requires structural nesting with code execution.
- **218 email forwarder alerts** — all external forwarders flagged on first scan. Now only alerts on valiases file changes.
- **178 suspicious_php_content alerts** — shell + request input co-presence. Now requires same-line proximity.
- **Hardening audit FPs** — Exim `+no_sslv2` parsed correctly; Dovecot uses `doveconf -a`; /tmp ignores setuid from virtmp; /etc/shadow accepts 0600.
- **Watchdog killing daemon every 5 min** — heartbeat was inside 10-min scan ticker. Dedicated goroutine now sends heartbeat independently.

### Added

- **Per-domain domlog brute force scanning** — scans `/home/*/access-logs/*-ssl_log` every 10 min. Catches wp-login/xmlrpc attacks invisible to the central access log on LiteSpeed.
- **Tail scanning for large PHP files** — detects payloads appended beyond 32KB head window.
- **Fragmented base64 detection** — catches function name splitting and massive concatenation payloads.
- **CGI backdoor detection** — fanotify watches `.pl/.cgi/.py/.sh/.rb` in `/home/` for non-PHP backdoors.
- **SEO spam detection** — gambling/togel dofollow link injection.
- **Brute Force dashboard card** — attack count, unique IPs, top 5 attackers with progress bars.
- **CRITICAL alerts bypass rate limit** — malware findings always dispatch. Default raised to 30/hour.
- **Auth failures hard-blocked** — API/FTP/PAM brute force bypasses PoW challenge, goes to nftables.
- **Quarantine sorted newest-first**.
- **xmlrpc.php POST blocked server-wide** — ModSec rule 900006 + auto-escalation to nftables block.

### Changed

- Default `max_per_hour` alert limit: 10 → 30.
- cPanel autoresponder/BoxTrapper pipes excluded from forwarder alerts.
- `spam_wp_footer_injection` YARA requires hidden/encoded/dofollow links.

## [2.0.0] - 2026-04-08

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
- **Web UI** — 14-page HTTPS dashboard (Tabler CSS) with audit log
- **Alerts** — email, Slack, Discord, generic webhooks
- **Auto-response** — process kill, file quarantine, IP blocking, subnet blocking, permblock escalation, 7 malware remediation strategies
- **PHP runtime shield** — via `auto_prepend_file`
- **WHM plugin** — single-pane-of-glass integration
- **WordPress plugin checker** — outdated plugin detection with WordPress.org API
- **Packaging** — RPM and DEB via nFPM, curl installer, deploy.sh upgrade script
- **Hardening audit** — on-demand server security audit with WHM Tweak Settings guidance, OS checks, SSH, PHP, mail, and firewall posture
- **GitHub Pages docs** — mdBook documentation auto-deployed on push

### Fixed

- Hardening audit: removed non-existent `disable-security-tokens` cPanel check (security tokens are mandatory since cPanel 11.38)
- Hardening audit: removed service subdomains check (disabling breaks Thunderbird/Outlook autodiscover)
- Hardening audit: fix messages now reference actual WHM UI labels and tabs instead of raw config keys
- Hardening audit: `/tmp` and `/var/tmp` permission check false positive — Go's `os.ModeSticky` uses high bits that don't map to Unix octal, causing `1777` to miscompare as `4000777`
- Hardening audit: skip Imunify360's internal PHP builds (`/opt/alt/php*-imunify/`) from PHP audit
- Installer: removed hardcoded infrastructure IPs and API tokens from default config

### Security

- Token auth with Bearer header and HttpOnly/Secure/SameSite=Strict cookie
- CSRF protection (HMAC-derived token) on all state-mutating endpoints
- Security headers: X-Frame-Options DENY, CSP, HSTS, X-Content-Type-Options
- TLS-only web UI with auto-generated self-signed certificate
- Rate-limited login (5/min per IP) and API (600/min per IP)
- Infrastructure IP protection: daemon refuses to block infrastructure CIDRs
- Commit-confirmed firewall apply with auto-rollback timer
- Sanitized all test data, documentation, and code comments of internal infrastructure details

[Unreleased]: https://github.com/pidginhost/csm/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/pidginhost/csm/releases/tag/v2.0.0
