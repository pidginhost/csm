# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Tightened 10 YAML detection rules to require their discriminator regex (proximity / co-occurrence in the same expression) instead of letting loose substring tokens accumulate to `min_match`. Affected: `webshell_wp_fake_plugin`, `exploit_wp_admin_creation`, `wp_cron_backdoor`, `network_port_scanner`, `spam_conditional_googlebot`, `backdoor_ssh_key_injection`, `dropper_telegram_exfil`, `dropper_php_input_stream`, `obfuscation_compact_unpack`, `deface_owned_by`. Stops FPs on Yoast SEO, Elementor importer, Monolog handlers, Jetpack/Mobile_Detect UA libs, phpseclib RSA/Blowfish, WPML translation API, and SmartBill REST client.
- Tightened 3 YARA rules to require proximity between signal terms: `miner_hidden_iframe` (was matching `marginwidth="0"` on WP oEmbed iframes), `deface_owned_by` (Google API field docs / PhpDocReader / WooCommerce CLI), `exfil_archive_send` (Elementor template export). All three now require build/heading/sink to co-occur in the same proximity window.
- `webshell_realtime` filename map (`shell.php`, `c99.php`, etc.) now requires content corroboration -- a request superglobal piped into a code-execution primitive, or eval/assert wrapping a base64/gzinflate decoder. Stops FPs on WP-bundled Pear `Text_Diff/Engine/shell.php`.
- `php_in_uploads_realtime` is content-aware: webshell markers stay Critical, clean PHP in uploads downgrades to Warning. Stops FPs on TinyMCE `smile_fonts/charmap.php` and similar bundled assets.
- `phishing_kit_realtime` now requires the filename to combine a brand (paypal/microsoft/office365/...) AND a phishing indicator (login/verify/secure/...). Dropped `kit` from the signal set since legitimate plugin slugs end in `-kit` (google-site-kit). Stops FPs on plugin distribution backups under `wpvividbackups/`.
- `email_suspicious_forwarder` realtime watcher establishes a baseline on first observation of a `valiases/<domain>` file and only alerts when the hash changes thereafter -- matches the scheduled audit's behaviour. Stops the alert flood every WHM-rsync account transfer caused.

### Changed

- `csm baseline`, `csm firewall *`, and `csm check*` now route through the daemon control socket instead of opening bbolt directly. Operational CLI commands no longer race the daemon for the bbolt lock. `csm store compact` still opens bbolt directly by design — it is documented as "daemon must be stopped."
- Control socket I/O buffer bumped from 1 MiB to 16 MiB on both endpoints so tier-run responses carrying full finding lists no longer risk hitting the scanner cap on servers with thousands of findings. The socket is root-only 0600, so the original DoS guard no longer applies.
- `csm firewall restart` and `csm firewall apply-confirmed` now require a live firewall engine; when the engine failed at daemon startup, recovery is via `systemctl restart csm` rather than the CLI re-connecting to nftables itself.
- `csm firewall deny-file` / `allow-file` chunk IPs on the client side (1000 per request) before dispatching to the daemon, so arbitrarily large blocklists round-trip without hitting any wire cap.

### Removed

- `csm-critical.timer` and `csm-deep.timer` systemd units. The daemon's internal scanners (10-min critical, 60-min deep) now own tier scheduling; prior timers duplicated the same work per interval. Upgrade postinstall stops/disables/removes the old units on existing 2.8.x hosts; fresh installs never see them.

## [2.8.1] - 2026-04-23

### Fixed

- Lint cleanup on top of 2.8.0 (gofmt realignment after the `YaraWorkerEnabled` type switch, govet-shadow `err` in the new retention tests, restructured `SweepReputationOlderThan`'s malformed-row skip so nilerr is satisfied). No runtime behaviour change; 2.8.0 and 2.8.1 are the same code path once compiled.

## [2.8.0] - 2026-04-23

### Added

- `retention:` config block (opt-in): per-bucket TTLs for `findings` / `history` / `reputation`, a `sweep_interval`, plus `compact_min_size_mb` and `compact_fill_ratio` knobs for the online bbolt compaction trigger. Schema, defaults, and validation only in this commit; the sweep goroutine and compaction primitive land in follow-up commits (ROADMAP item 6).
- `DB.SweepHistoryOlderThan`, `DB.SweepAttackEventsOlderThan`, `DB.SweepReputationOlderThan`: per-bucket age-based sweep primitives. Each runs in a single bbolt transaction — the history bucket uses lexicographic seek on the TimeKey prefix, attacks:events also prunes its secondary IP index, and reputation scans `CheckedAt` in the value. Malformed reputation rows are skipped rather than aborting the sweep.
- `DB.CompactInto` + `DB.Size`: bbolt online-compaction primitive wrapping `bolt.Compact` into a temp file and reporting src/dst sizes so operators can measure reclaimed space. The snapshot is taken under a View transaction on src, so quiescing writes around the subsequent file swap is the caller's responsibility (daemon wiring lands in the follow-up).
- `retention-scanner` daemon goroutine (opt-in via `retention.enabled`): runs `RunRetentionOnce` on `sweep_interval`, sweeping `history` (by `history_days`), `attacks:events` (by `findings_days`), and `reputation` (by `reputation_days`). Emits `csm_retention_sweeps_total` and `csm_retention_deleted_total` counters. When the on-disk file crosses `compact_min_size_mb`, the tick logs a "compaction recommended" hint.
- `csm store compact [--preview]` CLI subcommand: snapshots the live bbolt file with `CompactInto`, closes the source, and atomically renames the compacted copy over the live DB. Requires the daemon to be stopped (bbolt's file lock enforces this; a running daemon produces a clear "state DB is locked" error pointing operators at `systemctl stop csm`). `--preview` leaves the snapshot in place for inspection without touching the live DB.
- New email check `email_cloud_relay_abuse`: fires when a mailbox sends authenticated outbound mail from several distinct public-cloud IPs (GCP, AWS, Azure, DigitalOcean, Linode, Vultr, Oracle, Hetzner, OVH, Contabo) within the same hour, or when a single cloud IP sends in bulk past a volume threshold. Catches credential-abuse spam runs that stay under cPanel's per-hour hold threshold, which had left `email_compromised_account` silent — including paced attacks that deliberately use one IP/day to evade multi-IP stacking. Auto-suspends outgoing mail and auto-blocks the source IP via the existing nftables set; honors `high_volume_senders` allowlist. Thresholds (≥3 sends + ≥2 cloud IPs, or ≥15 sends from any cloud IPs, within 60 min) stay well above legitimate SaaS integrations like SmartBill and Nylas.
- Retrospective cloud-relay scan runs once at daemon startup on cPanel hosts: replays the last 24h of `exim_mainlog` through the same rule, so an in-progress credential-abuse spam run that started before CSM restarted (or before the rule existed) is surfaced within seconds of startup instead of waiting for the next real-time match. Findings trigger the same auto-suspend + auto-block path; per-user marker in the global store prevents re-emitting the same finding on repeated restarts.

### Changed

- README: added a "Storage & Retention" feature block (opt-in retention sweep, `csm store compact [--preview]`, hot-reload-safe fields) and updated the YARA-X bullet + CLI table to reflect the crash-isolated default. Cleaned up `docs/src/metrics.md` references to shipped ROADMAP items and added a dedicated Retention metrics section; `docs/src/development.md` now reflects default-on YARA worker with the tri-state opt-out.
- ROADMAP: shipped items (glibc builder, YARA-X process isolation, Prometheus `/metrics`, SIGHUP hot-reload, bbolt retention + compaction) condensed into "Related work already landed"; remaining pending work renumbered 1–4 (control socket phase 2, audit log export, backup/restore, challenge UX polish). Historical "ROADMAP item N" references in code/CHANGELOG preserved via a note at the top.
- `signatures.yara_worker_enabled` defaults to on. The field is now a *bool tri-state: omit it (or set `true`) to run YARA-X in the supervised child process; set `false` explicitly to keep the in-process scanner. Closes the ROADMAP item 2 default-flip follow-up — every upgrading host gets crash-isolated YARA-X without touching csm.yaml, and the escape hatch is preserved for operators who need it.
- Coverage badge pipeline no longer re-runs tests on GitHub Actions. The badge now reads the GitLab-produced `merged-coverage.out` from the latest release directly, so the public badge matches what CI measured instead of a drift-mangled re-merge. Removed `scripts/covmerge/`, which existed only to paper over that mismatch.
- Docs: sync reference pages against shipped code — Settings page + `/api/v1/settings/*`, `csm db-clean` subcommands, `signatures.yara_worker_enabled`, `sentry` config block, `firewall cf-status`; corrected the authenticated-page count to 15 and dropped a stale "future release" note about `account_roots`.

## [2.7.0] - 2026-04-22

### Added

- Dashboard now shows a single system health pill at the top, 24h stat cards carry day-over-day deltas and link into a pre-filtered history, and the trend chart has a 7d / 30d / 90d period selector.
- Live Feed on the dashboard has severity chips and a quick filter so busy hosts stay triageable during bursts.
- Web UI settings page: edit operator-facing config sections from the browser. Safe-reload sections apply live; restart-required sections save to disk and prompt for a one-click daemon restart.
- Settings: searchable, grouped multi-select for `alerts.email.disabled_checks` and `geoip.editions`. Backed by an authoritative check-name registry with a CI drift test.

### Changed

- Settings page redesign: grouped sidebar with icons, two-column form layout, sticky nav, dirty-state indicator per section, unsaved-changes prompt, and toast-based save feedback.
- Dashboard cards show a visible error state on API failure instead of a permanent "Loading...". "Last Critical" now ticks its relative time alongside the live feed.
- Removed the whole-page "System Overview" collapse toggle; it hid every card and had no useful scope.
- Every web UI page now carries a consistent page title; incident time-range picker matches the dashboard's button-group pattern.
- Loading placeholders and card-title icons aligned across pages; Threat "Auto-blocked" stat now links to the firewall.

### Fixed

- Dashboard "30-Day Trend" no longer flatlines on older days once the history bucket fills up. The chart now reads a pre-aggregated daily counter that survives history pruning, with a one-time backfill on first start.
- WAF rule check no longer false-alarms on cPanel + LiteSpeed hosts when cPanel is mid-rebuild of its vendor rule set. The filesystem probe now also covers LiteSpeed, so a transient empty response from whmapi1 is backstopped by the rules on disk.
- `config.YAMLEdit`: replacing an empty flow-style list (`foo: []`) with a multi-element value now falls back to block rendering instead of erroring with "cannot be rendered inline".

## [2.6.1] - 2026-04-20

### Added

- Unit-test coverage for the daemon control socket (`control_handlers.go`, `control_listener.go`) and YARA backend selector (`yara_backend.go`), all added in 2.5.0/2.6.0 with no tests. Covers dispatch routing (including a fuzz seed), every handler's argument clamping and error branches, end-to-end Unix-socket roundtrips with a `/tmp`-prefixed short path to avoid the macOS `sun_path` limit, the YARA worker restart rate-limiter, and the in-process backend init path. `controlSocketPath` became a `var` for test redirection; production default unchanged.
- Unit-test coverage for `internal/obs` (57% -> 93%) and the nil-client / pure-function paths of `internal/yaraworker/supervisor.go` (`RestartCount`, `ChildPID`, `toYaraMatches`, `DefaultSocketPath`, `Reload`/`RestartWorker` before-start error branches).
- Unit-test coverage for the plugin-checksum cache paths in `internal/wpcheck/plugins.go` (`pluginZipURL`, `FetchPluginChecksums`, `hasPluginChecksums`, `startBackgroundPluginFetch` dedupe, `fetchPluginWithRetry` success + exhaustion). HTTP routed via the existing `rewriteTransport`/`withTestHTTPClient` harness so no network is touched.
- Unit-test coverage for pure helpers in `internal/checks` (`countOccurrences`, `containsAny`, `isURLWordChar`) previously at 0%. All three are shared building blocks in higher-level checks; standalone tests pin their behaviour so a refactor cannot silently change the semantics.
- `attackdb.SetGlobal` and `attackdb.NewForTest` test hooks mirror the `store.SetGlobal` pattern: production wires `globalDB` exactly once through `Init`, tests install a pre-seeded DB without spawning the background saver. Unlocks full coverage of `CheckLocalThreatScore` (27% -> 100%) and the `apiThreatTopAttackers` / `apiThreatEvents` / `apiThreatStats` / `apiThreatDBStats` paths behind `attackdb.Global()`. `Global()` now also read-locks `globalMu`, matching `SetGlobal`; previously `Global` could race a goroutine reading `globalDB` while `Init` was assigning it inside `dbInitOnce.Do`. `NewForTest` deep-copies nested `AttackCounts` and `Accounts` maps so a later caller mutation cannot bleed into the DB.
- Unit-test coverage for the `internal/metrics` package-level shortcuts (`Default`, `MustRegister`, `RegisterCounterFunc`, `RegisterGaugeFunc`, `WriteOpenMetrics`) and `GaugeVec.writeTo`, previously at 0% because every existing test constructed a fresh `NewRegistry()` for isolation.

### Changed

- `analyzePHPContent` requires two converging indicators before returning Critical severity; the former single-indicator bypass for "remote payload" and "call_user_func with obfuscated" matches is gone. Heuristic hits still fire as High (`suspicious_php_content`) and reach the operator queue, but auto-quarantine in `AutoQuarantineFiles` no longer acts on a lone heuristic signal. YARA rule matches and realtime signature hits route through their own gates and are unchanged.
- Quarantine listing (`/api/v1/quarantine`) now hides entries whose archived content is byte-identical to the original path. Restoring a file (UI, CLI, or `cp`) removes the archive from the listing on next load without a separate cleanup step; divergent or missing originals remain visible.

### Fixed

- Webui "Apply fix" button left the finding visible after refresh when `Details` was set (e.g. `world_writable_php`, where the key is `check:message:<hash4>`). The fix chmod'd on disk but the server dismiss used `check:message` without the hash, so `DismissLatestFinding` silently no-op'd. Client now sends the canonical `data-key` from the enriched endpoint (and from the dashboard feed template) and the server prefers it over the legacy reconstruction.
- Auto-quarantine false positive on WPML's bundled PHPZip library (`inc/wpml_zip.php`). The "call_user_func with obfuscated function names" indicator fired on any file with file-wide hex literals plus a call_user_func anywhere; WPML's ZIP-format constants (`"\x50\x4b\x03\x04"`) + benign `call_user_func(self::$temp)` tripped it, hard-breaking wp-login on sites that `require_once` it at bootstrap. The check now requires hex escapes + concatenation on the call_user_func line itself, matching the LEVIATHAN pattern (`call_user_func("\x63"."\x75"."\x72"."\x6c", ...)`).
- `phishing_paypal` and `phishing_office365` rules in `configs/malware.yar` fired on any file containing a brand string plus `type="email"` in a form. Salient/Nectar theme's bundled Redux Framework tracking admin page tripped it via a PayPal donation link and a MailChimp email subscribe form. Both rules now require `type="password"`, which real credential harvesters always have and donation/subscribe widgets never do. The YAML `phishing_paypal` rule additionally dropped the "both brand strings" requirement so real phishing pages that only say "paypal" are now detected.
- Realtime fanotify scanner skips atomic-write staging files matching `.temp.<digits>.<name>.<ext>`. cPanel's fileTransfer service (and similar restore tools) write to these paths and rename(2) to the final filename; CSM's mask is CLOSE_WRITE + CREATE (no MOVED_TO), so the staged content was being scanned and the final target never was. A WordPress restore produced ~35 Critical signature/YARA alerts on legitimate WP core / plugin files in one burst. Lingering staging files (attacker hiding under the pattern without a follow-up rename) are still caught by the periodic deep scan.
- Three YAML rules over-fired on legitimate plugin code because their discriminating regex was optional. `obfuscation_assert_string` now requires the regex so plain `\assert(\is_array($x))` validation no longer fires (it only fires on `assert()` wrapping request input or decoder calls). `webshell_adminer_abuse` now requires the `adminer.org` upstream URL (WP security plugins that block Adminer mention the word in firewall rules but never contain the upstream URL). `spam_sitemap_hijack` now requires the hardcoded spam-TLD `<loc>` regex so legit sitemap generators (Rank Math, Yoast) that emit `<urlset>` XML do not trip it.
- Coverage badge workflow now authenticates the GitHub releases API and asset downloads with `GITHUB_TOKEN`. Anonymous calls from shared Actions runner IPs were hitting the 60 req/hour rate limit and returning 403, collapsing the 10-release walk to zero hits so the badge fell back to unit-only (52.2%) instead of merged (84.7%).

## [2.6.0] - 2026-04-19

### Added

- Optional Sentry crash reporting via a new `internal/obs` package wrapping `sentry-go`. A `sentry:` config block (`enabled`, `dsn`, `environment`, `sample_rate`, `debug`) toggles it; disabled or empty-DSN are no-ops. Long-lived daemon goroutines run through `obs.Go`/`obs.SafeGo` so panics land in Sentry with `component`/`os`/`panel`/`webserver` tags. DSN is redacted from `csm config show`.

### Changed

- YARA-X 1.14.0 -> 1.15.0 on the glibc-2.28 builder. Go binding API unchanged. `CSM_BUILDER_TAG` stepped to `glibc-2.28-r2`. The 1.15.0 attempt on the previous Alpine+musl-static builder crashed in `yrx_compiler_build`; the move to glibc-dynamic clears that.

### Added

- Emailav YARA-X adapter works under worker mode, closing ROADMAP item 2's last sub-item. `yaraipc.Match` and `yara.Match` gained `Meta map[string]string` (string-valued rule metadata); `emailav.YaraXScanner` reads severity from `Meta["severity"]` via `yara.Backend` instead of crossing the process boundary. Daemon and email-API UI switched from `yara.Global()` to `yara.Active()` for consistent behaviour under either backend.
- ROADMAP entries 4-9: Prometheus endpoint, audit log export, bbolt retention, SIGHUP hot-reload, baseline/state backup+restore, and challenge UX polish (CAPTCHA fallback, verified-session bypass, verified-crawler allow-pass).
- Internal `csm yara-worker` subcommand and `internal/yaraipc` wire protocol (length-prefixed JSON over Unix socket). Groundwork for moving YARA-X into a supervised child process so a cgo crash cannot take the daemon down (ROADMAP item 2); still in-process this release.
- `yaraworker.Supervisor` fork+execs the worker with exponential-backoff restart, readiness Ping, in-process `Reload`, and an escalation `RestartWorker`. Gated by `signatures.yara_worker_enabled` (default off); crashes emit a Critical `yara_worker_crashed` finding rate-limited to one per minute. Scan callers route through `yara.Active()`.
- `internal/metrics` package: Counter, Gauge, Histogram, their labelled vector variants, and a Registry that renders Prometheus text exposition format. Zero external deps. Groundwork for ROADMAP item 4.
- `/metrics` endpoint on the web UI (ROADMAP item 4 complete). Auth accepts `cfg.WebUI.MetricsToken` as a dedicated Bearer and falls back to UI AuthToken / session cookie. Eleven metrics shipped (`csm_build_info`, `csm_yara_worker_restarts_total`, `csm_findings_total`, `csm_store_size_bytes`, three `csm_fanotify_*` series, `csm_check_duration_seconds` with `{name,tier}` labels, `csm_blocked_ips_total`, `csm_firewall_rules_total`, `csm_auto_response_actions_total`). Documented in `docs/src/metrics.md`.
- Metrics hardening: per-subsystem smoke tests so a dropped `observe*` call site fails CI instead of surviving a manual scrape. New `docs/src/examples/prometheus-scrape.yml` plus a `promtool-check` CI job that validates it.
- `docs/src/configuration.md` "Editing csm.yaml by hand" section: documents the `csm rehash` step between a manual edit and `systemctl restart csm`. `integrity.Verify` refuses any config whose sha256 disagrees with `cfg.Integrity.ConfigHash` and crash-loops the daemon on restart, so the section covers backup / edit / rehash / validate / restart / rollback.
- SIGHUP config hot-reload (ROADMAP item 7, initial). `internal/config` gains `Active()`/`SetActive()` over `atomic.Pointer[Config]` and a `Diff()` that classifies top-level fields via a new `hotreload` struct tag. Fields tagged `safe` swap in place; untagged or `restart`-tagged fields abort the reload with a Warning `config_reload_restart_required` finding naming the offending fields, and the live config stays untouched. `Thresholds` is the first safe field. Parse/validation errors emit a Critical `config_reload_error` and keep the old config live. Reload re-signs `integrity.config_hash` in place. `ExecReload=/bin/kill -HUP $MAINPID` wired into the systemd unit. Known caveat: four long-lived tickers (`deep_scan_interval_min`, `wp_core_check_interval_min`, `webshell_scan_interval_min`, `filesystem_scan_interval_min`) keep firing at the old interval until restart; every other threshold takes effect next tick.

### Fixed

- False-positive quarantine storm on WP auto-updates and WPML. Deep-scan for `/wp-content/languages/` and `/wp-content/upgrade/` now runs content analysis first (matching the realtime path), the WPML translation queue is recognised as known-safe, and the auto-quarantine entropy floor is raised from 4.8 to 5.5 (WPML and Breakdance added to the library-path allowlist). A 2026-04-17 incident quarantined 109 benign files; the same content no longer trips any gate.
- Realtime `php_in_sensitive_dir_realtime` Warning no longer fires on WPML translation-queue regenerations. The fanotify path now shares `checks.IsSafePHPInWPDir` with the polled deep-scan, so a language-pack refresh no longer produces 30-40 Warnings per second.
- Realtime fanotify tests in `internal/daemon` stopped feeding `os.File.Fd()` into analyzer functions (`analyzeFile`, `checkCrontab`, `checkPHPContent`, `checkHtaccess`, `checkUserINI`, `checkHTMLPhishing`, `checkCGIBackdoor`). That pattern attached the netpoller and a GC finalizer to fds the tests then handed off to syscalling code, producing an intermittent EBADF under `-race` + coverage (CI job 93822). 11 test files converted to raw `unix.Open`/`unix.Close` fds, matching the production ownership model.
- WebUI "YARA RULES" card and "Reload Rules" button work under worker mode. The rules API was reading `yara.Global()` (nil when the worker is on, so the dashboard reported 0); it now uses `yara.Active()`, covering both backends.
- `runPeriodicChecks` no longer fires a spurious Critical `integrity` tamper alert on every tier tick after a successful SIGHUP reload. `integrity.Verify` was passed the startup `d.cfg` whose `ConfigHash` went stale as soon as reload re-signed the on-disk file; it now runs against `d.currentCfg()`. Regression: `TestReloadConfigIntegrityVerifyPassesAfterReload`.
- SIGHUP reload no longer misclassifies every reload as `restart_required` from a false-positive firewall diff. `startFirewall` was merging `cfg.InfraIPs` into `d.cfg.Firewall.InfraIPs` at boot, so a fresh post-reload config (without that merge) diffed non-equal even on an unedited file. The merge now uses a shallow-copied `FirewallConfig` and leaves `d.cfg.Firewall` untouched. Caught on live production smoke (2026-04-19). Regression: `TestDiffLoadLoadIsEmpty`.
- A SIGHUP reload rejected as `restart_required` no longer leaves the on-disk file with a stale `integrity.config_hash` that would crash-loop the daemon on next restart. The handler now re-signs the file via `integrity.SignAndSaveAtomic` on that branch and updates the live `config.Active()` ConfigHash in lock-step, so between edit and restart `integrity.Verify(currentCfg)` does not see a disk/memory divergence. Also caught on live production smoke. Regression: `TestReloadConfigRestartRequiredKeepsIntegrityConsistent`.
- `firewall: netlink receive: recvmsg: no buffer space available` on startup and every SIGHUP. `Engine.loadState` was issuing one `SetAddElements` call per persisted entry, overflowing the netlink socket's `SO_RCVBUF` on hosts with a few hundred blocks. Entries are now collected per target set and shipped via a new `addElementsChunked` helper that caps each message at 1000 elements (~28 KB, below the 208 KB rmem default); 1000 is even so interval sets never split a `{start, IntervalEnd}` pair.
- Firewall `resolveSubnetSet` and `loadState`'s blocked_net loop skip cleanly when `lastIPInRange` returns nil (malformed `net.IPNet` whose IP is neither 4 nor 16 bytes). Prior code fell through to `nextIP(nil)` and fed an empty Key to the kernel. Regression: `TestResolveSubnetSetMalformedIPReturnsNil`.
- `plugincheck` no longer double-logs one hung wp-cli call as both `Command timed out` and `JSON parse failed: unexpected end of JSON input`, and stderr chatter (PHP warnings, MySQL deprecation notices, broken-plugin backtraces) can no longer poison the JSON (the `invalid character 'W'/'P'/'N'` class). wp-cli runs through a new stdout-only `CmdRunner.RunContextStdout` that surfaces `context.DeadlineExceeded`, plus `--skip-plugins --skip-themes` and `WP_CLI_PHP_ARGS='-d display_errors=0 -d error_reporting=0'` so one broken plugin can't tip the whole enumeration into exit 255. Per-site failure lines replaced by a single refresh summary with `timeout=N exec_fail=N json_fail=N` counters.

### Changed

- SIGHUP hot-reload safe-reload set grows from one field to six: `alerts`, `suppressions`, `auto_response`, `reputation`, and `email_protection` are now tagged `hotreload:"safe"` alongside `thresholds`. Auto-response paths, `alert.Dispatch`, and the heartbeat read `d.currentCfg()` per call; batch handlers (`dispatchBatch`, initial-scan) snapshot once at the top so a reload landing mid-batch never splits a finding set between policies. Regression: `TestDiffAllSafeFieldsClassifiedSafe`.

- `csm run-deep` no longer exits with `reading response: i/o timeout` on large servers. Tier-run RPCs get a 60-minute deadline (plugin-cache refresh fans out a wp-cli per site); other CLI commands keep the 5-minute default. The hourly `csm-deep.service` timer now logs a real `tier=deep findings=X new=Y elapsed_ms=Z` line instead of failing every hour.
- `db_post_injection` stopped firing on legacy author-embedded `<script src="http://...">` tags. Post-content URL classification uses a post-specific predicate that drops the plaintext-HTTP indicator but keeps structural markers (raw IP, abused TLD, known-bad exfil host, invalid host). wp_options classification is unchanged.
- `suspicious_php_content` no longer fires purely on "shell function co-present with request input" against WordPress file-manager plugins (FileOrganizer, elFinder). The co-presence signal is corroboration only; same-line shell-function-with-request-input still fires alone. `containsStandaloneFunc` also rejects method calls, static calls, and function declarations (e.g. an SQLite driver's `$this->DB->...(...)` line with a `$_SERVER` reference no longer trips the same-line rule).
- `webshell_p0wny` dropped the bare `"p0wny"` pattern. Combined with the `p0wny.?shell` regex it double-counted on a single occurrence of "p0wny-shell" (e.g. a docblock reference), clearing `min_match: 2` on its own. The remaining patterns (`featureShell`, `makeCommand`, `window.term`) are structural markers unique to the shell's terminal UI.
- AbuseIPDB quota enforcement persists across 10-minute cycles: a 429/402 backs off until the next UTC midnight, a per-day counter (cap 900) acts as a circuit breaker, and transient-error cache entries expire at the intended ~1h (the pre-fix formula shifted `CheckedAt` into the future, effectively stretching error caches to ~11h).

## [2.5.0] - 2026-04-17

### Security

- Go toolchain 1.26.1 -> 1.26.2, clearing 6 stdlib CVEs flagged by govulncheck in reachable code paths (crypto/x509, crypto/tls, archive/tar, html/template). govulncheck now clean.
- Added CodeQL SAST workflow (push / PR / weekly) and SHA-pinned the remaining GitHub Actions.
- Crontab heuristic now catches the `base64 -d|bash` pipe chain (with and without spaces, and `--decode` form) used by the 2026-03-24 gsocket "defunct-kernel" persistence seen in production. Single source of truth for the pattern list kills previous drift between the system and per-account scans.
- `suspicious_crontab` findings now have a real `ApplyFix` handler: the user crontab is copied to `/opt/csm/quarantine/` with a restore-ready metadata sidecar and the live file is truncated to zero bytes. Before this change the fix button advertised a cleanup it never performed.
- Crontab pattern check now runs a single base64 decode pass over each cron line, catching attacker variants that wrap the `base64 -d|bash` chain in an outer base64 layer so no literal markers appear in the cron file as written. Bounded: 16 candidates per file, 8 KB per blob, depth 1.
- Real-time fanotify watch on `/var/spool/cron/` emits `suspicious_crontab` Critical the instant a user crontab is written, instead of waiting for the next 10-minute polled scan. Best-effort directory mark; root crontab drift is still tracked via the polled baseline hash.

### Added

- Daemon control socket at `/var/run/csm/control.sock` (0600, root-only). The CLI commands `run`, `run-critical`, `run-deep`, `status`, `update-rules`, and `update-geoip` now route through the running daemon instead of opening their own bbolt handle. This eliminates the `store: opening bbolt: timeout` error from timer-spawned scans racing the daemon for the database lock. Commands that don't need bbolt (`validate`, `verify`, `rehash`, `update-rules`, `update-geoip`) no longer open it. Remaining migrations (`baseline`, `firewall`, `check-*`) are tracked as phase 2 in `ROADMAP.md`.
- Dashboard "Top Attack Types" card scoped to 24h via a new `by_type_24h` JSON field so it matches the adjacent 24h timeline instead of showing lifetime totals.
- 16 `go test -fuzz` targets for parsers that accept attacker-controlled input (log-line extractors, finding-message parsers, config parsers, low-level decoders). Seeds double as regression tests; five seconds of fuzzing per target finds no crashers.

### Fixed

- `phishing_office365` dropped its forgeable `namespace\s+(?:EasyWPSMTP|WPMailSMTP|FluentMail)` exclude. An attacker could silence the Critical alert by pasting `<!-- namespace EasyWPSMTP -->` into a cloned Microsoft login page. The rule now keys on DOM IDs and JS variables copied verbatim from login.microsoftonline.com (`i0116`, `i0118`, `idSIButton9`, `urlMsaSignUp`/`urlResetPasswordMsa`) with `require_regex: true`; legitimate SMTP plugin admin views (FluentSMTP, WP Mail SMTP, Easy WP SMTP) do not mimic the login DOM and no longer need an allow-list entry. The DOM-ID regexes additionally accept HTML-entity-encoded attribute quotes (`&#34;` / `&#x22;` / `&quot;` and their single-quote variants), closing a second bypass where the browser decodes the entities at parse time but a literal-quote regex would not match the raw bytes.
- `backdoor_php_auto_append` `exclude_regexes` no longer lists `php_shield` as a safe directive target. CSM's own php_shield is ini-activated (in `/opt/cpanel/ea-phpXX/root/etc/php.d/`), never written to .htaccess, so an attacker who dropped `php_shield.php` and pointed `auto_prepend_file` at it was bypassing the rule. The Go heuristic in `checkHtaccess` already omitted it; this aligns the YAML rule with it.
- `checkHTMLPhishing` dropped the early `return` on `/wp-admin/`, `/wp-includes/`, `/wp-content/themes/`, `/wp-content/plugins/`, `/node_modules/`, `/vendor/`, and `/.well-known/`. An attacker who compromised any of those directories could drop a Microsoft/Google/Dropbox credential-harvesting page and the alert never fired. The content gates (credential inputs + brand impersonation + exfil sink or trust badge) are strong enough to reject legitimate framework HTML, so the path-allowlist was pure attack surface.
- `exploit_wp_config_stealer` dropped its `exclude_patterns: ["define('DB_PASSWORD'"]` short-circuit, which a stealer could forge with a decoy comment. The rule's `min_match: 3` already requires the `file_get_contents` regex to fire, and stock `wp-config.php` does not call `file_get_contents` on itself, so the exclusion added nothing but attack surface.
- `php_in_uploads_realtime` no longer suppresses Critical alerts based on a path-substring allowlist (`/sucuri/`, `/smush/`, `/imunify`, `/cache/`, etc.). An attacker-created directory named after any listed token was enough to hide a dropped webshell. PHP in `wp-content/uploads/` is now either a Warning (structurally-verified plugin-update temp dir) or Critical; operators whitelist specific daemons via the path-scoped suppressions API, which is explicit and audited.
- `htaccess_injection_realtime` and the `backdoor_php_auto_append` signature rule no longer accept loose substring tokens (`"litespeed"`, `"rsssl"`, `"php_shield.php"` anywhere on the line) as safe markers. Exclusions are now anchored to the actual `auto_(prepend|append)_file` directive target, and `base64_decode` / PHP-eval tokens only get a pass when they appear inside a `RewriteCond` / `RewriteRule` (real defensive attack-blocklists). A forged `# litespeed` comment no longer silences either detector.
- `webshell_content_realtime` in `checkPHPContent` no longer short-circuits on the string `wp_filesystem`. The exclusion was forgeable: a webshell pasting `/* wp_filesystem */` as a comment suppressed the Critical alert. The same-line shell-function-plus-request-input check that follows is the actual detection and handles real WP_Filesystem admin pages on its own (their `$wp_filesystem->put_contents(...)` calls are not in the scanned shell-func list).
- Plugin-verification hardening (review fixes on top of the feature above): per-ZIP-entry decompression cap stops zip-bomb entries that fit under the compressed download cap but expand past it; `filepath.Clean` + `..`/absolute-path rejection on ZIP entry names prevents a crafted ZIP from landing path-traversal keys in the checksum map; failed plugin fetches now retry with the same 1 min / 5 min / 15 min / 1 h backoff the core fetch uses, keeping the in-flight flag set across attempts so a 404 does not produce a fresh goroutine per file-write event; reconcile loop wraps open+analyse+close in an inline function so a panic in `analyzeFile` cannot leak the fd.
- WordPress plugin file verification extends the existing core-file path. `wpcheck` now detects plugins via `/wp-content/plugins/<slug>/`, reads the `Version:` header from the main plugin file, and background-fetches the official ZIP from `downloads.wordpress.org`. Per-file SHA256 hashes are cached per slug/version; a file whose on-disk content matches the cached hash skips signature and YARA evaluation, the same treatment core files already got. Paid plugins without a wordpress.org release (WPML, Salient) fall through to normal rule evaluation and benefit from items 1-3 above.
- fanotify analyzer queue raised from 1000 to 4000 events, and directories that had events dropped are now reconciled once a minute: the overflow reporter walks each drop-dir and scans any interesting file modified within the last 70 seconds. During a 2026-04-17 production unzip event 7,900+ events were dropped and lost; the reconcile pass converts that into a delayed scan instead of a blind spot.
- `php_in_sensitive_dir_realtime` for `/wp-content/languages/` and `/wp-content/upgrade/` no longer fires Critical purely on path. Content analysis now runs first: if a real rule hits, that Critical is the signal; clean files still surface as a Warning so unexpected PHP in these directories stays visible. Eliminates the per-file Critical storm during WPML translation-queue writes and WordPress core auto-updates while preserving detection of actual backdoors dropped there.
- Four YARA rules no longer fire on stock WordPress plugin code. `backdoor_htaccess_auto_prepend` now ignores PHP source files that document the directive in translated UI strings (Wordfence WAF installer views). `backdoor_iconcache_disguise` dropped the over-broad variable-variable + decoder arm that matched WPML translation packages; the suspicious-filename and `shell_exec`+decoder arms still fire. `mailer_mass_sender` (YARA) now requires the `mail(` call to sit within 500 bytes of a loop keyword and rejects substring matches inside `is_email(`/`wp_mail(`. `spam_wp_footer_injection` now requires either the `dofollow` marker or an actually echoed external link with a hide-it style, instead of `display:none` or `base64_decode` alone.
- Five signature rules (`mailer_mass_sender`, `exfil_archive_send`, `dropper_fgc_eval`, `spam_wp_options_inject`, `deface_owned_by`) no longer fire on stock WordPress plugin code (Wordfence, WPML, Contact Form 7, Twig, Freemius). Each now requires its tightening regex to match rather than just two substring hits; `deface_owned_by` additionally requires surrounding HTML page tags so the phrase in a PHP docblock no longer trips it.
- `db_post_injection` no longer flags legitimate third-party widget embeds (cookie-consent tools, document-embed services, regional video/form widgets). Detection now requires concrete attacker markers in the script URL; exfiltration hosts, raw-IP loaders, abused-TLD hosts, and plaintext HTTP scripts continue to fire.
- `db_spam_injection` no longer flags prose mentions of pharma/gambling keywords in legitimate business content (industry listings, advisor bios, catalogs). Findings now require an SEO-cloaking or injection signal alongside the keyword.
- `perf_wp_config` no longer produces noise for operator-set PHP values in cPanel-managed `.user.ini` files. Suppression is scoped strictly to `.user.ini` via the cPanel MultiPHP INI Editor header.
- Dashboard "Findings Timeline (24h)" and "30-Day Trend" no longer let Critical's stacking/fill obscure High and Warning.
- Threat Intelligence "Attack Trend (24h)" bar labels were off-by-one; they now read "23h..1h..now" anchored on the right edge.

### Changed

- Build toolchain moved from Alpine+musl-static to AlmaLinux 8+glibc-dynamic. The musl-static configuration was not a toolchain upstream YARA-X exercises, and the eight consecutive builder-image iterations it took to link YARA-X 1.15.0 were symptomatic. Binaries now target a glibc 2.28 floor — every modern cPanel host (CloudLinux/Alma/RHEL 8+, Ubuntu 22.04+) meets this. YARA-X itself stays statically linked into the binary; only glibc and a handful of standard system libraries link dynamically. A new CI check fails the build if any referenced glibc symbol exceeds `GLIBC_2.28`. Linux/arm64 ships via docker buildx + QEMU user-mode emulation, producing genuine arm64 machine code at the same `GLIBC_2.28` floor as amd64; the arm64 builder image is a manually-triggered one-time build per YARA-X version. Linux/arm64 binaries also regain the real YARA-X scanner — earlier arm64 builds silently shipped a no-op stub because the cross-toolchain omitted the `yara` build tag. See `ROADMAP.md` item 1 for the full decision record.
- Bumped Go dependencies: `go.etcd.io/bbolt` 1.4.0 -> 1.4.3, `spf13/cobra` 1.8.1 -> 1.10.2, plus the x/sys, x/net, x/crypto, x/term, x/text, pflag, netlink, netns families. `VirusTotal/yara-x/go` stays pinned at 1.14.0 — the attempt to move to 1.15.0 was retracted (see the yanked 2.4.3 note below) and will only be re-attempted on a branch with local reproduction coverage.
- `release:github` GitLab job runs automatically on tag pipelines (was manual-click; already gated on `/^v/` tags and `allow_failure: true`).

## [2.4.3] - 2026-04-16 [YANKED 2026-04-17]

**This release was yanked.** The dependency bump from
`VirusTotal/yara-x/go` 1.14.0 to 1.15.0 produced a binary that
crashed with SIGSEGV inside `yrx_compiler_build` on every daemon
startup, putting affected servers into a systemd restart loop.
The GitHub release was removed and the `v2.4.3` tag deleted.

All entries that were originally listed under this version have
been moved into `[Unreleased]` and will ship with the next
release, minus the YARA-X 1.15.0 bump (which remains deferred).

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

- Fixed the WHM plugin never appearing in the WHM Plugins sidebar. Two separate bugs: (a) `internal/daemon/configs/csm.conf` used a fake schema with keys like `implements=whostmgrd`, `label=`, `group=` that no version of cPanel understands -- replaced with the documented `service=whostmgr` / `displayname=` / `entryurl=` / `user=root` / `target=_self` schema matching clamavconnector and whm-360-monitoring; (b) the daemon wrote the file but never invoked `/usr/local/cpanel/bin/register_appconfig`, so WHM's registration database never picked it up. Added a `registerWHMPlugin` helper that runs after the file is written, with a 30s timeout and non-fatal failure handling. Verified the plugin now appears in `whmapi1 get_appconfig_application_list` in production.
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
