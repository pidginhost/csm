# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- New `internal/platform` package that detects the host OS (Ubuntu, Debian, AlmaLinux, Rocky, RHEL, CloudLinux), control panel (cPanel, Plesk, DirectAdmin), and web server (Apache, Nginx, LiteSpeed). The daemon logs the detected platform at startup (`platform: os=... panel=... webserver=...`) so operators can verify auto-detection without running a separate command.
- CSM now runs on plain Ubuntu+Nginx and AlmaLinux+Apache hosts in addition to the original cPanel+Apache target. On non-cPanel hosts it watches the correct per-distro auth log (`/var/log/auth.log` on Debian family, `/var/log/secure` on RHEL family), correct web server access/error logs (`/var/log/nginx/*` or `/var/log/httpd/*` or `/var/log/apache2/*`), and skips cPanel-only watchers (exim mail log, WHM session log, `/etc/valiases` forwarder watcher) that used to log "not found, retrying every 60s" forever.
- WAF check now detects ModSecurity on Apache and Nginx across Debian and RHEL family distros, scans the correct per-distro config candidates and rule directories (`/etc/apache2/mods-enabled/`, `/etc/httpd/modsecurity.d/`, `/etc/nginx/modsec/`, `/usr/share/modsecurity-crs/rules/`, …), and emits platform-specific install hints (`apt install libnginx-mod-http-modsecurity`, `dnf install --enablerepo=epel mod_security`, …) instead of always telling the operator to open WHM.
- `CheckRPMIntegrity` now dispatches to `debsums` (preferred) or `dpkg --verify` (fallback) on Debian/Ubuntu hosts, reporting modified system binaries with the same scope as the existing `rpm -V` path on RHEL family.

### Fixed

- Fixed `csm baseline` and `csm rehash` producing a config hash that did not match the file the daemon reads on startup, causing the daemon to reject its own config with "config hash mismatch" on fresh installs. The hash is now computed after `config.Save` rewrites the file, so it matches the bytes on disk.
- Fixed `.deb` and `.rpm` packages flattening the `ui/` and `configs/` directory trees, which broke the Web UI (it expects `ui/templates/` and `ui/static/` subdirectories) and dropped the `configs/whm/` subdirectory entirely. `build/nfpm.yaml` now lists each subdirectory explicitly instead of relying on a bare directory glob.
- Fixed `scripts/install.sh` and `scripts/deploy.sh` pointing at the wrong GitHub release asset name (`csm-linux-amd64` instead of `csm-VERSION-linux-amd64`), causing downloads to fail with HTTP 404. Both scripts now resolve the latest tag from the GitHub API and build the correct versioned asset path.
- Fixed `scripts/install.sh` and `scripts/deploy.sh` aborting with `CSM_SIGNING_KEY_PEM is not set; refusing unsigned install` when no signing key is provided, even though release signatures are not yet published. Signature verification is now skipped with a warning when no key is configured.
- Fixed `CheckRPMIntegrity` silently losing every finding because `rpm -V`, `debsums -c`, and `dpkg --verify` all exit non-zero to signal "problems found"; the old code treated non-zero exit as command failure and discarded the output. Added `runCmdAllowNonZero` helper that preserves output on `*exec.ExitError` and reuses it across all three backends.
- Fixed `checkRuleAge` only scanning files one directory level deep, missing the flat distro CRS layouts (`/etc/modsecurity/`, `/etc/httpd/modsecurity.d/activated_rules/`, `/usr/share/modsecurity-crs/rules/`) where rule files live directly in the configured directory. Stale-rules alerts now fire on Debian/RHEL hosts, not just cPanel.
- Fixed `CheckModSecAuditLog` using a hardcoded Apache/cPanel-only candidate list; it now consults `platform.Detect().ModSecAuditLogPaths` so Nginx and RHEL-family Apache hosts are covered.
- Fixed `wafInstallHint`, `wafRulesHint`, and `wafRulesStaleHint` always pointing the operator at "WHM > Security Center > ModSecurity" regardless of panel; hints are now platform-specific (`apt install`, `dnf install`, WHM instructions only on cPanel).
- Fixed `discoverAccessLogPath` and `discoverModSecLogPath` using static cPanel-biased candidate lists; both now consult `platform.Detect()` and match the detected OS + web server.
- Fixed the platform binary-fallback in `detectWebServer` preferring Nginx over Apache when both binaries are installed but neither is running; on dual-installed cPanel hosts the fallback now prefers Apache (cPanel's primary), and the cPanel-compiled httpd under `/usr/local/apache/bin/httpd` is detected even when it is not in PATH.
- Fixed `Info.ApacheConfigDir` pointing at `/etc/httpd` on cPanel+CloudLinux hosts; cPanel compiles Apache from source under `/usr/local/apache/conf`, which the platform detector now uses when `IsCPanel()` is true.

## [2.1.1] - 2026-04-09

### Fixed

- Fixed challenge routing extracting version numbers from informational findings as IP addresses, causing legitimate IPs to be blocked. Challenge routing now uses a closed allowlist of checks known to contain attacker IPs — unlisted checks are safely skipped.
- Fixed legitimate WordPress admin users being blocked by user enumeration detection when using Gutenberg or Elementor.
- Improved ModSecurity rule precision for REST API user enumeration detection.

## [2.1.0] - 2026-04-09

### Fixed

- Closed the remaining email AV tempfail gaps so scan timeouts and infected-mail quarantine failures can defer delivery instead of silently falling back to delivery.
- Made remote rule-update authenticity mandatory by requiring `signatures.signing_key` for YAML and YARA Forge updates, and by refusing unsigned installer/deployer downloads when no signing key PEM is configured.
- Extended check timeout cancellation into the main long-running filesystem and WordPress scan paths so timed-out checks stop more of their background work instead of only reporting a timeout.
- Hardened quarantine restore and release paths in the Web UI and email AV so metadata-backed restore operations are constrained to trusted destination roots and pre-clean quarantine entries remain addressable for preview, restore, and deletion.
- Closed several privileged file-operation escapes in automated remediation by preferring structured file paths, rejecting symlinks, and enforcing account-root and allowed-root boundaries before chmod, quarantine, or `.htaccess` cleanup actions run.
- Made PAM brute-force telemetry functional and harder to spoof by emitting failure events from the PAM module, clearing counters on success, restricting the listener socket, and authenticating Linux peers before accepting login events.
- Applied suppression rules before daemon auto-response so known false positives no longer continue to auto-fix files, challenge clients, or block IPs after an operator suppresses them.
- Fixed temporary subnet-block expiry semantics so expired subnet rules are pruned from both persisted firewall state and the live engine instead of silently surviving restart or heartbeat gaps.
- Unified finding identity across alert deduplication, state tracking, UI dismissal, and latest-findings storage so findings that differ by `Details` no longer lose history or evade dismissal.
- Added bounded and strict JSON decoding on mutating Web UI APIs to reduce authenticated memory-pressure and malformed-body abuse against privileged endpoints.
- Tightened the MIME and ClamAV mail path by capping large body buffering before decode and surfacing unexpected clamd responses as scanner errors instead of classifying them as clean mail.
- Switched config loading to reject unknown YAML keys and made config integrity hashing fail on scanner errors instead of silently hashing only a prefix of malformed input.
- Persisted attack-database deletions to the bbolt store so expired or manually removed IP records do not return after restart.
- Rejected hidden ModSecurity bookkeeping rules in the apply API so direct callers cannot disable counter rules that visible enforcement depends on.
- Made YARA and YAML signature reloads atomic and fail-closed on invalid rule material, preserving the previous live ruleset instead of silently accepting partial coverage.
- Validated downloaded GeoIP `.mmdb` files before installation so update success is only reported after the extracted database can actually be opened.
- Fixed expired temporary allow rules being restored on daemon startup by filtering them during state load, matching the existing behavior for blocked IPs and subnets.
- Fixed allowlist source collision where DynDNS, challenge, and manual allows overwrote each other. Allow entries are now keyed by IP+Source; removing one source no longer removes allows from other sources.
- Fixed challenge Apache rewrite redirecting to `127.0.0.1` (the client's loopback) instead of the server's public hostname.
- Hardened challenge server's IP extraction to only trust `X-Forwarded-For` from configured `trusted_proxies`, preventing IP spoofing to mint firewall allow rules for arbitrary addresses.
- Fixed reflected XSS in challenge post-verification redirect by sanitizing the destination URL to same-origin paths and HTML-escaping it before embedding in the meta refresh tag.
- Fixed check runner timeout cancellation leak by adding `context.Context` to all check functions. Timed-out checks now receive a cancellation signal instead of leaking goroutines indefinitely.
- Added configurable `fail_mode: tempfail` for email AV scanning so operators can choose to defer mail delivery (Exim retries) when all scan engines are unavailable, instead of the default fail-open delivery.
- Added ed25519 signature verification for automatic rule updates. When `signatures.signing_key` is configured, both YAML and YARA Forge rule downloads are verified against a detached `.sig` file before installation.
- Added ed25519 signature verification framework to install, deploy, and GitLab deploy scripts. When a signing key PEM is embedded in the script, binary downloads are verified before installation.

### Added

- `challenge.trusted_proxies` config: list of IPs allowed to set X-Forwarded-For in challenge requests.
- `emailav.fail_mode` config: `"open"` (default) or `"tempfail"` to defer mail when scanners are down.
- `signatures.signing_key` config: hex-encoded ed25519 public key for verifying rule updates.
- Ed25519 signature verification module (`internal/signatures/verify.go`) with tests.
- `RemoveAllowIPBySource` firewall method for source-aware allow removal.
- Regression tests covering remediation path validation, PAM listener behavior, state-key consistency, suppression path matching, attack DB deletion persistence, integrity scanner failures, ModSecurity bookkeeping-rule protection, YARA/signature reload safety, GeoIP database validation, MIME body budget enforcement, and ClamAV unknown-response handling.

## [2.0.2] - 2026-04-08

### Added

- Firewall web UI response console with direct block, subnet, allow, trusted-IP, lookup, and cPanel lockout cleanup workflows from one page.
- Firewall activity drill-down with provenance labels, blocked-entry filters, and recent-action inspection tied to IP lookup.

### Changed

- Refined the firewall page around operator workflows: richer state summaries, allow-rule visibility, safer response actions, and clearer audit context.
- Simplified the top-level access workflow by replacing separate "allow" and "whitelist" cards with a single trust model that distinguishes firewall-only access from fully trusted IP handling.
- Streamlined the firewall action cards into compact, labeled operator forms with single-field IP-or-CIDR blocking and cleaner trust-mode transitions.

## [2.0.1] - 2026-04-08

### Fixed

- Corrected tagged-release versioning so published assets use the release version consistently.
- Reduced false positives in WordPress attack and PHP-content detection.

### Added

- Hardened malware detection against common evasion patterns while keeping coverage for suspicious `.htaccess` prepend/append directives.

### Changed

- Tightened release metadata and artifact naming in CI for tagged builds.

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

[Unreleased]: https://github.com/pidginhost/csm/compare/v2.0.2...HEAD
[2.0.2]: https://github.com/pidginhost/csm/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/pidginhost/csm/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/pidginhost/csm/releases/tag/v2.0.0
