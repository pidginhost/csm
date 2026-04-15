# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.2] - 2026-04-15

### Security

- gosec is now a blocking pipeline job (no longer `allow_failure: true`). Every remaining finding from the 336-finding baseline has been either fixed (decompression-bomb cap, permission tightening, cookie Secure flag, JSON-in-script escape) or inline-annotated with `// #nosec G### -- <reason>`. New findings will fail CI until they're fixed or explicitly justified.

### Added

- More unit-test coverage for webui and checks since 2.4.1: `apiQuarantinePreview` + `apiQuarantineRestore` + `apiQuarantine` listing, `apiGeoIPLookup` / `apiGeoIPBatch` error branches, `CheckWPTransientBloat` guards, `CheckDNSConnections` all branches → 100%, `CheckShadowChanges` root/bulk/upcp branches 76% → 94%, `collectRecentIPs` across all log sources → 100%, `queryAbuseIPDB` 429/API-error/transport-failure branches → 96%, `findWPTransients` recursion + mysql dispatch 71% → 85%, `AutoRespondDBMalware` + `parseDBFindingDetails` → 100%, and `buildFileIndex` dispatcher branches. Plus `internal/webui/quarantineDir` converted to a `var` so quarantine tests can redirect under `t.TempDir()` (production default unchanged).

### Fixed

- Integration job on GitLab replaced the blind `sleep 45` after `phctl compute server create` with an SSH readiness poll (5 s interval, 240 s ceiling). Fixes intermittent "Connection timed out" failures when the Ubuntu image takes longer than 45 s to bring sshd up.
- Coverage badge workflow now walks the 10 most recent GitHub releases looking for `merged-coverage.out` instead of only probing `releases/latest`. A freshly-cut tag whose integration profile hasn't been uploaded yet no longer drops the badge to unit-only.

## [2.4.1] - 2026-04-15

### Security

- Fanotify realtime analyser no longer lets malicious `.htaccess`, `.user.ini`, or `.config` executables staged under `/tmp`, `/dev/shm`, or `/var/tmp` bypass detection. Specific file-type checks now run before the generic tmp early-return.
- Tightened permissions on CSM-private paths: state dir 0700, WP checksum cache 0700/0600, YARA Forge tmpfile 0600.
- Web UI JSON-in-`<script>` embedding routes through a single escape helper that neutralises `<`, `>`, `&`, U+2028, U+2029, closing an XSS vector if attacker-controlled fields contain `</script>`.
- PoW challenge verification cookie (`csm_verified`) sets `Secure`; CSM is HTTPS-only.
- GeoIP mmdb extraction rejects tar entries larger than 500 MiB (decompression-bomb guard).

### Fixed

- `extractFilePath` iterated `/home, /tmp, /dev/shm, /var/tmp` in that order, so `/var/tmp/x.php` was silently classified as `/tmp/x.php` (substring match), pointing auto-response at the wrong file. Now longest-prefix-first.
- `extractPID` only terminated on comma, returning strings like `"42 exe=/bin/ls"` instead of `"42"`. Now also stops on whitespace/newline.
- `extractPHPDefine` only parsed quoted values, so `define('DISABLE_WP_CRON', true);` returned empty and `CheckWPCron` emitted false-positive findings on correctly configured installs. Now handles unquoted bool/number literals.

### Added

- CI security tooling: `gosec` and `govulncheck` jobs (GitLab), OSSF Scorecard workflow (weekly), Dependabot (weekly for `gomod` and `github-actions`), `make sec`/`make vuln` targets, and Go Report Card / Scorecard / pkg.go.dev / release / license README badges.
- Pinned versions across CI: golangci-lint v2.11.4, gosec v2.25.0, govulncheck v1.2.0, golang 1.26.2, GitHub Actions SHA-pinned.
- `scripts/covmerge`: tolerant Go coverage profile merger for the badge pipeline. Dedupes per-file entries on read and merges per range-key, so source drift between unit and integration profiles no longer drops whole files.

### Changed

- `CheckFirewall`, `verifyDoveadm`, `extractWPDomain`, and `refreshPluginCache` route external commands through the `cmdExec` injector instead of `exec.Command` directly. Production unchanged; tests can now mock `nft`/`doveadm`/`wp-cli`. Coverage on these paths 0–58% → 93–100%.
- `quarantineDir`, `eximSpoolDirs`, and the per-action `fix*AllowedRoots` lists in `internal/checks/remediate.go` are vars (not consts) so tests can redirect remediation under `t.TempDir()`. Production defaults unchanged.

## [2.4.0] - 2026-04-14

### Added

- SMTP brute-force detection. New real-time tracker aggregates `dovecot_login authenticator failed` events from `/var/log/exim_mainlog` into three signals: `smtp_bruteforce` (per-IP, auto-blocks the IP), `smtp_subnet_spray` (per-/24, auto-blocks the whole subnet), and `smtp_account_spray` (per-mailbox, visibility only). Tunable via the new `thresholds.smtp_bruteforce_*` keys in `csm.yaml`.
- Mail brute-force detection for IMAP, POP3, and ManageSieve. Real-time tracker for `/var/log/maillog` runs alongside the existing Dovecot geo-login monitor (composition preserves `email_suspicious_geo`). Emits `mail_bruteforce` (per-IP, auto-blocks), `mail_subnet_spray` (per-/24, auto-blocks the whole subnet), `mail_account_spray` (per-mailbox, visibility only), and `mail_account_compromised` (successful login from an IP that was just brute-forcing the same mailbox; auto-blocks). Tunable via the new `thresholds.mail_bruteforce_*` keys.
- Admin-panel brute-force detection. Real-time counter for POSTs to phpMyAdmin (`/phpmyadmin/index.php`, `/pma/index.php`, `/phpMyAdmin/index.php`) and Joomla (`/administrator/index.php`) login endpoints. Emits `admin_panel_bruteforce` at 10 POSTs per 5 minutes per IP and auto-blocks. Drupal and Tomcat Manager are intentionally not covered yet because they need different path semantics and a different attack-shape detector.

## [2.3.2] - 2026-04-14

### Fixed

- Coverage badge merge pipeline no longer silently fails when `gocovmerge` emits stderr output. The GitHub Actions workflow now redirects stderr separately and validates the merged profile before using it. Both unit and integration runs now use `-covermode=atomic` so their profiles are mergeable.

### Added

- 30+ new E2E integration tests covering filesystem, auth, brute-force, web, system, exfiltration, WHM/SSH, DNS/SSL, phishing, PHP content, hardening, WAF, mail, and network Check* functions on real AlmaLinux/Ubuntu servers.
- More unit tests: `CheckForwarders` 10% -> 100%, `CheckPHPProcesses` 21% -> 96%, `doGeoIPUpdate` 27% -> 73%.

## [2.3.1] - 2026-04-14

### Changed

- Coverage badge now reflects both unit and integration test coverage. The GitLab integration pipeline publishes the merged profile as a GitHub release asset, and the GitHub Actions badge workflow fetches it and merges with the unit profile so Linux-specific code (fanotify, nftables, YARA, PAM) counts toward the percentage.

### Added

- 800+ new tests across every package. checks ~75%, daemon ~70%, webui ~70%, store/threat/mime ~90%. Coverage for WAF auditing, autoresponse, email scanning, WordPress plugin detection, firewall state management, daemon orchestration, and HTTP API handlers.
- Linux-tagged unit tests for previously uncovered platform-specific code: fanotify file monitoring helpers, spoolwatch mail permission management, nftables engine state and CIDR loaders.

## [2.3.0] - 2026-04-13

### Added

- Automatic database malware response. When CSM detects a malicious external script injection in WordPress database options, it now blocks attacker IPs extracted from active WordPress sessions, revokes compromised sessions, and cleans the malicious content. Enabled via `auto_response.clean_database: true`.
- `csm baseline` now requires `--confirm` when history data exists to prevent accidental loss of the 30-day trend chart, firewall state, and per-account findings.
- `csm db-clean` CLI for operator-initiated WordPress database cleanup: `--option` removes malicious scripts from wp_options (with backup), `--revoke-user` revokes sessions and optionally demotes to subscriber, `--delete-spam` removes published spam posts matching known patterns. All commands support `--preview` for dry-run.
- Expanded test coverage to 65%+ (Linux CI). 500+ test functions across all packages. OS/CmdRunner dependency injection enables mock-based testing of all 62 Check* functions.
- Integration test infrastructure: CI spins up real AlmaLinux/Ubuntu cloud servers via phctl, deploys CSM, runs nftables and fanotify tests, collects coverage, and tears down servers automatically.

### Fixed

- Fixed `-short` flag in both GitLab CI and GitHub Actions workflows which was skipping tests. Fixed data race in wpcheck httpClient test swap.

## [2.2.2] - 2026-04-12

### Added

- Added code coverage reporting on both CI sides with no SaaS dependencies. GitLab's `test` job now emits a Cobertura report and a per-job coverage percentage (`gocover-cobertura` converts Go's native `-coverprofile` output), so merge requests show inline coverage deltas in the diff viewer. GitHub's `pages.yml` workflow runs `go test -coverprofile` on each push to main, generates a self-contained SVG coverage badge with a dynamic color band (red -> brightgreen at 90%+) plus an interactive HTML coverage drill-down via `go tool cover -html`, and ships both alongside the mdbook docs in the GitHub Pages artifact at `https://pidginhost.github.io/csm/coverage.svg` and `/coverage.html`. The README links the SVG badge to the HTML report so the pair survives the `git push --mirror --force` mirror refresh.
- Added targeted regression coverage for the realtime daemon parsers and handlers. New tests cover cPanel File Manager write detection, API 401 handling, stale-session suppression after password purges, webmail login detection, WordPress brute-force thresholding/dedup, session-log direct login vs portal session handling, SSH accepted-login parsing, and Exim/Dovecot parsing for frozen messages, credential leaks, auth failures, outgoing-mail hold dedup, and outbound rate-limit attribution.
- Added focused `AutoBlockIPs` regression tests for four high-risk stateful paths: challenge-listed IPs are skipped instead of hard-blocked, hourly rate limiting queues IPs instead of dropping them, queued IPs drain and block on the next cycle, and repeat offenders are promoted from temporary blocks to permanent blocks once the configured escalation threshold is reached.

### Fixed

- Fixed `internal/checks.ThreatDB.loadPersistedWhitelist` spawning a fire-and-forget goroutine (`go db.saveWhitelistFile()`) to rewrite `whitelist.txt` when expired entries were dropped during startup load. On a fast daemon shutdown the goroutine could race the process exit and leave a `whitelist.txt.tmp` temp file behind or write a half-serialized file depending on where the kill landed between `os.WriteFile` and `os.Rename`. The rewrite now runs synchronously -- the load path runs once at startup, the cost is negligible on any realistic whitelist size, and the file state is guaranteed consistent when the load returns. Discovered via a coverage-building test suite whose `t.TempDir()` cleanup raced the background goroutine and reported "directory not empty" on teardown.
- Fixed `daemon.parseFTPLogLine` failing to extract the client IP from standard pure-ftpd log messages. pure-ftpd prefixes every syslog line with `(user@addr)` -- for example `pure-ftpd: (?@203.0.113.5) [WARNING] Authentication failed for user [alice]`. The previous extractor scanned for a whitespace-separated field starting with a digit, but the `(?@203.0.113.5)` field starts with `(`, so the IP was never found and `ftp_auth_failure_realtime` / `ftp_login_realtime` alerts never fired on real hosts. A new `extractPureFTPDClientIP` helper now parses the prefix, returns the IP if `addr` is a valid IPv4/IPv6 literal, and returns empty for reverse-resolved hostnames (cPanel's default with `DontResolve=no`) since a hostname cannot be enforced at the firewall. The old bare-IP scanner is retained as a fallback for unusual syslog formats. Operators who run with the default cPanel `DontResolve=no` and want FTP brute-force alerts to fire should set `DontResolve=yes` in `/etc/pure-ftpd.conf` so the IP, not the hostname, is logged.
- Fixed a hang in `alert.redactSensitive` when redacting populated password values. The function ran an outer `for {}` loop that re-searched the whole string after each replacement, which re-found the same `password=` prefix at the same position and re-wrote the already-inserted `[REDACTED]` marker back into `[REDACTED]` forever. Any alert whose `Message` or `Details` contained a populated `password=` / `pass=` / `passwd=` / `new_password=` / `old_password=` / `confirmpassword=` pair would wedge the daemon's `Dispatch` call. Discovered when a coverage test ran for 600 seconds before the Go test timeout killed it. The loop now tracks a `searchFrom` offset and advances it past the replacement (or past an empty-value occurrence) so the same position cannot be matched twice.
- Fixed `internal/checks.parseWPConfig` returning garbage credentials for every real WordPress install. `extractDefine` stripped the literal key string and called `extractPHPString` on the remainder, which for `define( 'DB_NAME', 'wordpress_db' );` was `', 'wordpress_db' );`. `extractPHPString` then returned the substring between the FIRST pair of quotes it found -- the closing quote of `'DB_NAME'` and the opening quote of `'wordpress_db'` -- which is `", "`. Every field (`dbName`, `dbUser`, `dbPass`, `dbHost`) came back as `", "`, and `CheckWPDatabase` invoked `mysql` with garbage arguments that silently failed. The entire WordPress database scan feature was non-functional on real cPanel hosts. `extractDefine` now steps past the first comma after the key before calling `extractPHPString`, so the value's opening quote is picked up correctly. File-system-level malware detection was unaffected.
- Fixed `internal/challenge.sanitizeRedirectDest` accepting opaque `javascript:` and other non-HTTP URI schemes. The scheme whitelist check was gated on `if parsed.Host != ""`, so opaque URLs produced by `url.Parse("javascript:alert(1)")` (which have Host="" and Scheme="javascript") skipped scheme validation entirely and ended up reconstructed as `"javascript:"` instead of `"/"`. Modern browsers block `javascript:` in `<meta http-equiv="refresh">` targets, so exploitation was limited in practice, but the function's documented invariant ("return a safe same-origin relative path or absolute URL matching the request host") was violated. The scheme whitelist now runs unconditionally and rejects anything outside `{"", "http", "https"}`, catching `javascript:`, `data:`, `file:`, and any future opaque scheme.
- Fixed `platform.Overrides.Panel` and `platform.Overrides.WebServer` silently ignoring explicit "none" overrides. Both fields were typed as their underlying string enum, with the sentinel `PanelNone`/`WSNone` defined as `""`, and `applyOverrides` skipped them via `if o.Panel != "" { ... }` -- which cannot distinguish "not overriding" from "overriding to none". An operator who wanted to explicitly tell CSM "this host has no control panel" (or "no web server") had no way to express that through the override API. Both fields are now `*Panel` / `*WebServer` pointers: nil leaves the auto-detected value alone, and a non-nil pointer always wins -- including when it points at `PanelNone`/`WSNone`. The only production caller (`internal/daemon/daemon.go`) builds the pointer conditionally from the config's optional `web_server.type` field, so zero-value configs behave exactly as before. Found via a coverage-building test suite that probed the override API.
- Fixed the DNF install one-liner in `docs/src/installation.md` failing on non-interactive installs with `repomd.xml GPG signature verification error: Signing key not found`. On the first `dnf install csm` after adding the repo, dnf imports the repo signing key and prompts "Is this ok [y/N]:" to trust it. The `-y` flag answers package install prompts but not the key-trust prompt, so non-interactive installs saw the prompt go unanswered and the key never persisted. The documented install flow now runs `rpm --import https://mirrors.pidginhost.com/csm/csm-signing.gpg` before adding the repo so the key is already in the RPM keyring when dnf checks the repomd.xml signature.
- Fixed `waf_status` and `waf_rules` overstating protection on some non-cPanel hosts. Nginx module-loader files (`load_module ... modsecurity`) no longer count as "WAF active" unless a real enablement directive such as `modsecurity on;` or `modsecurity_rules_file ...` is present in a live Nginx config, and the rule-presence check now looks for actual ModSecurity rule artifacts (`.conf`, `.data`, `.rules`) instead of treating any non-empty directory under `/etc/modsecurity` or `/etc/nginx/modsec` as evidence that rules are loaded.
- Fixed the distro EOL audit passing CentOS 8. CentOS is now treated as end-of-life regardless of major version, with an explicit migration recommendation instead of the previous "8+" policy shortcut.
- Fixed `perf_wp_cron` still hardcoding `/home/*/public_html` after the new `account_roots:` support landed. It now uses `ResolveWebRoots`, matching `perf_error_logs`, `perf_wp_config`, and `perf_wp_transients`, so non-cPanel Ubuntu/AlmaLinux layouts like `/var/www/*/public` or `/srv/sites/*/public` are scanned consistently.
- Fixed cPanel hosts with Nginx in front of Apache sometimes tailing the wrong realtime logs. Platform detection now prefers LiteSpeed or Apache over reverse-proxy Nginx on cPanel, and the cPanel Apache log paths are ordered ahead of distro defaults so access-log and ModSecurity watchers follow the origin server log stream by default.
- Fixed LiteSpeed going undetected on hosts where it ships as the `litespeed` systemd unit. The `runningServices` probe list only included `lshttpd`/`lsws`, and there is no binary-path fallback for LiteSpeed, so those hosts fell through to `WSNone` (or whichever other web server binary happened to be installed). The unit probe list now includes `litespeed` alongside `lshttpd`/`lsws`.

## [2.2.1] - 2026-04-10

### Added

- **APT and DNF package repositories** at `https://mirrors.pidginhost.com/csm/`. Users can now `apt install csm` on Debian/Ubuntu or `dnf install csm` on AlmaLinux/Rocky/RHEL/CloudLinux and receive future releases via the normal `apt upgrade` / `dnf upgrade` path. Repository metadata is GPG-signed. The last 5 tagged releases are retained, enabling `apt install csm=X.Y.Z-1` / `dnf downgrade csm` for rollbacks. See [installation.md](docs/src/installation.md) for the one-liner setup commands.

### Fixed

- Fixed the WHM plugin never appearing in the WHM Plugins sidebar. Two separate bugs: (a) `internal/daemon/configs/csm.conf` used a fake schema with keys like `implements=whostmgrd`, `label=`, `group=` that no version of cPanel understands -- replaced with the documented `service=whostmgr` / `displayname=` / `entryurl=` / `user=root` / `target=_self` schema matching clamavconnector and whm-360-monitoring; (b) the daemon wrote the file but never invoked `/usr/local/cpanel/bin/register_appconfig`, so WHM's registration database never picked it up. Added a `registerWHMPlugin` helper that runs after the file is written, with a 30s timeout and non-fatal failure handling. Verified the plugin now appears in `whmapi1 get_appconfig_application_list` on cluster6.
- Fixed the GitLab `publish` and `cleanup:packages` CI jobs only running on main-branch pipelines, so tag pipelines produced versioned binaries for GitHub Releases but did not update the internal GitLab Generic Package Registry. As a result, `/root/deploy-csm.sh upgrade` on cPanel hosts always pulled the main-branch build (with `git describe` version string like `2.1.1-7-ge814e6b`) instead of the tagged release (`2.2.0`). Both jobs now also run on version tags (`/^v/`); future releases will ship the properly-versioned binary to both registries.
- Fixed the Comodo WAF rule description table mislabeling rules in the 21xxxx range (`210710`, `210381`, `214930`, `218420`) as "OWASP:" when they are actually from the Comodo vendor ruleset (`/etc/apache2/conf.d/modsec_vendor_configs/comodo_litespeed/`). Added a code comment explaining the vendor prefix convention (21xxxx = Comodo, 9xxxxx = OWASP CRS) so future edits don't repeat the mistake.
- Fixed two usability bugs on the "Recent Firewall Activity" panel in the Web UI: (a) the "Clear filters" button was a cramped col-md-1 icon-only button with no visible label and no column label above it, now widened to col-md-2 with an invisible spacer label and a proper "Clear filters" text label alongside the × icon; (b) clicking Inspect on an audit row previously jumped the user back to the top-of-page Lookup section and reshuffled the audit table via a filter change, now opens the firewall/GeoIP details in an inline expansion row directly below the clicked button, with toggle-to-close and automatic cleanup when the filter or search inputs change.

## [2.2.0] - 2026-04-10

### Added

- **Multi-platform support.** CSM now runs on plain Ubuntu 20.04+ / Debian 11+ / AlmaLinux 8+ / Rocky 8+ / RHEL 8+ in addition to cPanel/CloudLinux. A new `internal/platform` package auto-detects the host OS, control panel (cPanel, Plesk, DirectAdmin, or none), and web server (Apache, Nginx, LiteSpeed) at daemon startup. The detected platform is logged at startup (`platform: os=... panel=... webserver=...`) and drives the per-OS choice of log paths, config candidates, and check set. cPanel-only watchers (session log, exim mainlog, `/etc/valiases` forwarder, exim spool) are skipped cleanly on non-cPanel hosts instead of spamming "not found, retry every 60s". See `docs/src/installation.md` for the supported-platforms matrix.
- **WAF detection for Nginx and RHEL-family Apache.** The `waf_status` check now detects ModSecurity on Apache and Nginx across Debian and RHEL family distros, scans the correct per-distro config candidates and rule directories (`/etc/apache2/mods-enabled/`, `/etc/httpd/modsecurity.d/`, `/etc/nginx/modsec/`, `/usr/share/modsecurity-crs/rules/`), and emits platform-specific install hints (`apt install libnginx-mod-http-modsecurity`, `dnf install --enablerepo=epel mod_security`, etc.) instead of always telling the operator to open WHM.
- **System integrity checks on Debian/Ubuntu.** `CheckRPMIntegrity` now dispatches to `debsums` (preferred) or `dpkg --verify` (fallback) on Debian/Ubuntu hosts, reporting modified system binaries with the same scope as the existing `rpm -V` path on RHEL family.
- **`web_server:` config override section** lets operators pin the web server type, config directory, access log paths, error log paths, and ModSecurity audit log paths on hosts with custom layouts. Every field is optional and falls back to auto-detection. Applied via `platform.SetOverrides` at daemon startup so every check sees the merged view. Includes a `panel` override for hybrid setups. See `docs/src/configuration.md`.
- **`account_roots:` config option** plus new `checks.ResolveWebRoots` helper that expands glob patterns to web root directories. Lets operators point the account-scan based performance checks (`perf_error_logs`, `perf_wp_config`, `perf_wp_transients`) at non-cPanel layouts like `/var/www/*/public` or `/srv/http/*`. Remaining account-scan checks still assume the cPanel `/home/*/public_html` layout and will be migrated incrementally.
- **`internal/log` package** wraps `log/slog` with a custom `legacyTextHandler` that preserves the historical `[YYYY-MM-DD HH:MM:SS] msg` format in text mode (so mixing structured calls with legacy `fmt.Fprintf` calls produces a uniform log stream). Operators opt into JSON-formatted logs for Loki/ELK/Datadog by setting `CSM_LOG_FORMAT=json`; `CSM_LOG_LEVEL` controls verbosity. ~15 daemon startup log lines (platform detected, daemon starting/running, watching log, PAM listener active, fanotify file monitor active, initial scan complete, firewall active, cloudflare whitelist enabled, systemd watchdog active, challenge server active, ...) now emit structured records.
- **Release signing infrastructure** in `.gitlab-ci.yml`. New `sign` stage produces `.sig` files for every binary, package, and asset tarball using an ed25519 key from the `CSM_SIGNING_KEY` CI variable. Install and deploy scripts read the public key from the `EMBEDDED_SIGNING_KEY` variable (currently empty -- operator provisions the key per `docs/src/release-signing.md`). Existing release behavior is preserved when no key is configured; set `CSM_REQUIRE_SIGNATURES=1` to enforce strict signature verification.
- **Fuzz tests for all 10 log parsers** (`parseModSecLogLine`, `parseAccessLogBruteForce`, `parseAccessLogLineEnhanced`, `parseSecureLogLine`, `parseEximLogLine`, `parseSessionLogLine`, `parseFTPLogLine`, `parseDovecotLogLine`, `parsePHPShieldLogLine`, `parseModSecLogLineDeduped`) in `internal/daemon/parsers_fuzz_test.go`. Each survives arbitrary input without panicking; ~70M total executions across all parsers found zero crashes in initial fuzzing. Run ongoing with `go test -fuzz=FuzzParseModSecLogLine -fuzztime=60s ./internal/daemon/`.
- **`make sync-embedded` and `make check-embedded` targets** to keep the go:embed copy of `deploy.sh` in sync with `scripts/deploy.sh`. The GitLab lint stage fails if they drift.

### Fixed

- Fixed `csm baseline` and `csm rehash` producing a config hash that did not match the file the daemon reads on startup, causing the daemon to reject its own config with "config hash mismatch" on fresh installs. The hash is now computed after `config.Save` rewrites the file, so it matches the bytes on disk.
- Fixed `.deb` and `.rpm` packages flattening the `ui/` and `configs/` directory trees, which broke the Web UI (it expects `ui/templates/` and `ui/static/` subdirectories) and dropped the `configs/whm/` subdirectory entirely. `build/nfpm.yaml` now lists each subdirectory explicitly instead of relying on a bare directory glob.
- Fixed `scripts/install.sh` and `scripts/deploy.sh` pointing at the wrong GitHub release asset name (`csm-linux-amd64` instead of `csm-VERSION-linux-amd64`), causing downloads to fail with HTTP 404. Both scripts now resolve the latest tag from the GitHub API and build the correct versioned asset path.
- Fixed `scripts/install.sh`, `scripts/deploy.sh`, and `scripts/deploy-gitlab.sh` aborting with `CSM_SIGNING_KEY_PEM is not set; refusing unsigned install` when no signing key is provided, even though release signatures were not yet published. Signature verification is now skipped with a warning when no key is configured, and a missing `.sig` file (404) is treated as "unsigned release" rather than a hard failure. Set `CSM_REQUIRE_SIGNATURES=1` to re-enable strict enforcement.
- Fixed `CheckRPMIntegrity` silently losing every finding because `rpm -V`, `debsums -c`, and `dpkg --verify` all exit non-zero to signal "problems found"; the old code treated non-zero exit as command failure and discarded the output. Added `runCmdAllowNonZero` helper that preserves output on `*exec.ExitError` and reuses it across all three backends.
- Fixed `checkRuleAge` only scanning files one directory level deep, missing the flat distro CRS layouts (`/etc/modsecurity/`, `/etc/httpd/modsecurity.d/activated_rules/`, `/usr/share/modsecurity-crs/rules/`) where rule files live directly in the configured directory. Stale-rules alerts now fire on Debian/RHEL hosts, not just cPanel.
- Fixed `CheckModSecAuditLog` using a hardcoded Apache/cPanel-only candidate list; it now consults `platform.Detect().ModSecAuditLogPaths` so Nginx and RHEL-family Apache hosts are covered.
- Fixed `wafInstallHint`, `wafRulesHint`, and `wafRulesStaleHint` always pointing the operator at "WHM > Security Center > ModSecurity" regardless of panel; hints are now platform-specific (`apt install`, `dnf install`, WHM instructions only on cPanel).
- Fixed `discoverAccessLogPath` and `discoverModSecLogPath` using static cPanel-biased candidate lists; both now consult `platform.Detect()` and match the detected OS + web server.
- Fixed the platform binary-fallback in `detectWebServer` preferring Nginx over Apache when both binaries are installed but neither is running; on dual-installed cPanel hosts the fallback now prefers Apache (cPanel's primary), and the cPanel-compiled httpd under `/usr/local/apache/bin/httpd` is detected even when it is not in PATH.
- Fixed `Info.ApacheConfigDir` pointing at `/etc/httpd` on cPanel+CloudLinux hosts; cPanel compiles Apache from source under `/usr/local/apache/conf`, which the platform detector now uses when `IsCPanel()` is true.
- Fixed fresh `curl | bash` installs ending up without `/opt/csm/deploy.sh`: `scripts/install.sh` tried to copy it from `/opt/csm/configs/deploy.sh` which never existed. Deploy.sh is now shipped via three independent paths: the `.deb`/`.rpm` package (`build/nfpm.yaml`), the `csm-assets.tar.gz` tarball that `install.sh` extracts, and a separate release asset fallback in `install.sh` that curls it from GitHub if the tarball doesn't ship it.
- Fixed `internal/daemon/configs/deploy.sh` (the `go:embed` copy of `deploy.sh` that the daemon writes to disk on every startup) drifting from the canonical `scripts/deploy.sh`. Previously, any fix to the deploy script was silently reverted on the next daemon restart because the embedded copy overwrote it. The files are now kept in sync by the `make sync-embedded` target plus a CI lint check that fails on drift.

## [2.1.1] - 2026-04-09

### Fixed

- Fixed challenge routing extracting version numbers from informational findings as IP addresses, causing legitimate IPs to be blocked. Challenge routing now uses a closed allowlist of checks known to contain attacker IPs -- unlisted checks are safely skipped.
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

- **Real-time file monitor** -- fanotify-based detection of webshells and malware in < 1 second
- **Log watchers** -- inotify on cPanel, SSH, FTP, Exim, and webmail auth logs (~2s detection)
- **PAM brute-force listener** -- real-time blocking on SSH/FTP/cPanel login failures
- **Critical scanner** -- 34 checks every 10 minutes (processes, network, auth, reputation)
- **Deep scanner** -- 28 checks every 60 minutes (filesystem, WP integrity, phishing, DB)
- **nftables firewall** -- kernel netlink API, IP/subnet blocking, rate limiting, country blocking
- **ModSecurity management** -- rule deployment, per-domain overrides, escalation control, web UI
- **Signature engine** -- YAML + YARA-X dual scanner with hot-reload and auto-fetch from YARA Forge
- **Email AV** -- ClamAV + YARA-X scanning of Exim spool and attachments
- **Challenge pages** -- SHA-256 proof-of-work for gray-listed IPs (CAPTCHA alternative)
- **Threat intelligence** -- AbuseIPDB, GeoIP (MaxMind), attack correlation, IP scoring
- **Performance monitor** -- PHP, MySQL, Redis, WordPress, OOM detection
- **Web UI** -- 14-page HTTPS dashboard (Tabler CSS) with audit log
- **Alerts** -- email, Slack, Discord, generic webhooks
- **Auto-response** -- process kill, file quarantine, IP blocking, subnet blocking, permblock escalation, 7 malware remediation strategies
- **PHP runtime shield** -- via `auto_prepend_file`
- **WHM plugin** -- single-pane-of-glass integration
- **WordPress plugin checker** -- outdated plugin detection with WordPress.org API
- **Packaging** -- RPM and DEB via nFPM, curl installer, deploy.sh upgrade script
- **Hardening audit** -- on-demand server security audit with WHM Tweak Settings guidance, OS checks, SSH, PHP, mail, and firewall posture
- **GitHub Pages docs** -- mdBook documentation auto-deployed on push

### Fixed

- Hardening audit: removed non-existent `disable-security-tokens` cPanel check (security tokens are mandatory since cPanel 11.38)
- Hardening audit: removed service subdomains check (disabling breaks Thunderbird/Outlook autodiscover)
- Hardening audit: fix messages now reference actual WHM UI labels and tabs instead of raw config keys
- Hardening audit: `/tmp` and `/var/tmp` permission check false positive -- Go's `os.ModeSticky` uses high bits that don't map to Unix octal, causing `1777` to miscompare as `4000777`
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
