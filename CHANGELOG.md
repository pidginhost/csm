# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- ModSecurity rule management page in the web UI (view, reload, manage rules)
- ModSecurity escalation exclusion UI on the Rules page
- Outdated WordPress plugin detection deep scan check with 24-hour cache refresh
- WordPress.org API client for plugin version comparison
- Plugin cache storage methods in bbolt store
- `CSM.fetch()` wrapper with 30s AbortController timeout and error toast
- `CSM.poll()` utility with exponential backoff and visibility-change pause/resume
- `CSM.debounce()` utility for input handler throttling
- CSS custom properties (`--csm-*`) for severity colors with dark/light theme support
- Tooltips across all web UI pages (dashboard, findings, history, firewall, threat)
- ARIA labels on all icon-only buttons for screen reader accessibility
- `aria-expanded` attributes on collapsible sections in findings page
- `PID` field on `Finding` struct for structured process identification
- Atomic `droppedAlerts` counter on daemon with accessor method
- `LastUpdated` timestamp and `FeedsStale()` method on threat feed database
- `BruteForceWindow` config field (default 5000) for configurable tail window
- Config validation enforced on daemon startup (errors cause exit, warnings logged)
- Fanotify drop event logging every 100 drops for early warning
- State file `.bak` backups before loading (guards against corruption)
- MIT license (LICENSE)
- Contributing guidelines (CONTRIBUTING.md)
- Security policy with responsible disclosure process (SECURITY.md)
- This changelog (CHANGELOG.md)

### Changed
- Dashboard charts replaced with Chart.js (removed hand-rolled SVG rendering)
- All web UI API calls routed through `CSM.apiUrl` for correct WHM reverse-proxy support
- Chart colors now read from CSS custom properties via `getComputedStyle`, auto-update on theme switch
- Replaced 35+ silent `.catch(function(){})` handlers with `console.error` or `CSM.toast`
- All `setInterval` calls tracked and cleaned up on `beforeunload`/`visibilitychange`
- Search inputs across all pages debounced at 300ms via `CSM.Table`
- Credential log detection threshold raised from 3 to 5; config file paths now excluded
- JSONL history writes skipped when bbolt is available (deprecation warning on fallback)
- Finding dedup key now includes truncated Details hash to prevent key collisions
- `.gitignore` hardened with IDE, env, cert, and OS file patterns

### Fixed
- **Security:** Command injection in firewall rollback — replaced `bash -c` with pure Go
- **Security:** TOCTOU race in file remediation — added `filepath.EvalSymlinks()` + path validation
- **Security:** PID extraction from free text — uses structured `Finding.PID` field first
- **Security:** Silent JSON unmarshal failures — errors logged, `.bak` backups created
- Goroutine leak in alert dispatcher shutdown — added 30s context timeout
- Auto-quarantine cross-device file duplication — check remove error, delete copy on failure
- Silent error suppression on critical paths (state save, remediate writes, store close)
- ModSecurity: deduplicate Apache and LiteSpeed events; filter server IPs from domain lists
- ModSecurity: fallback field extraction for old raw-format findings
- ModSecurity: structured details for consistent field extraction; events search added
- ModSecurity: downgrade individual block alerts from CRITICAL to HIGH
- ModSecurity: suppress block and escalation alerts from email/webhook dispatch
- ModSecurity: show rule descriptions for LiteSpeed-only events
- ModSecurity: exclude rule 900112 from auto-block escalation
- Dashboard history page truncation fixed
- Deep scan findings are now preserved across daemon restarts
- `csm scan` command no longer requires the bbolt lock (can run alongside daemon)
- HTTP/2 disabled on web UI to fix `ERR_HTTP2_PROTOCOL_ERROR` on long-running scans
- Write deadline extended for scan endpoint; unused findings payload removed
- Outdated plugin findings suppressed from email/webhook alert dispatch
- Several golangci-lint issues resolved in ModSec rule management

## [1.0.0] - 2025-01-01

### Added
- fanotify real-time file monitor (< 1 second detection)
- inotify log watchers for cPanel, SSH, FTP, Exim, and webmail
- PAM brute-force listener with real-time IP blocking
- 31 periodic critical checks (every 10 minutes)
- 18 periodic deep checks (every 60 minutes) including WordPress core integrity
- nftables firewall engine via kernel netlink API (replaces LFD/fail2ban)
- YAML and YARA-X signature rule engine with hot-reload
- Web UI: dashboard, findings, history, quarantine, firewall, threat intel, incidents, rules, audit
- GeoIP integration via MaxMind GeoLite2 City and ASN databases with auto-update
- Email AV orchestration: ClamAV and YARA-X scanning of Exim spool
- Threat intelligence: IP reputation scoring, attack correlation, top-attacker tracking
- Auto-response: process kill, file quarantine, IP blocking, subnet blocking, permblock escalation
- PHP runtime shield via `auto_prepend_file`
- Proof-of-work challenge server for suspicious IPs
- WHM plugin integration for single-pane-of-glass access
- RPM and DEB packaging via nFPM; curl installer; deploy.sh upgrade script
- ModSecurity audit log watcher with Apache and LiteSpeed format support
- ModSecurity CSM-rule threshold escalation to auto-block

### Security
- Token auth with Bearer header and HttpOnly/Secure/SameSite=Strict cookie
- CSRF protection (HMAC-derived token) on all state-mutating endpoints
- Security headers: X-Frame-Options DENY, CSP, HSTS, X-Content-Type-Options
- TLS-only web UI with auto-generated self-signed certificate
- Rate-limited login (5/min per IP) and API (600/min per IP)
- Infra IP protection: daemon refuses to block infrastructure CIDRs
- Commit-confirmed firewall apply with auto-rollback timer

[Unreleased]: https://github.com/your-org/cpanel-security-monitor/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-org/cpanel-security-monitor/releases/tag/v1.0.0
