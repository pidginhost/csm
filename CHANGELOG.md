# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Fixed the suspicious-login country detector never firing on the production dovecot log format: both known login-success line formats are now recognized by every mail detector.
- An IP with good login history no longer gets brute-force leniency against mailboxes it never legitimately used: good standing now only vouches for the mailboxes where it was earned. Note this can auto-block an office IP that repeatedly fails a mailbox it has never authenticated to.
- Fixed the store migration renaming the firewall's state file after copying it into unused buckets, which silently dropped all pre-upgrade blocks and allows from enforcement on the first boot after upgrading.
- Reduced state database churn from busy incidents: bookkeeping-only updates now coalesce to at most one write every few seconds per incident, while open, escalate, and close transitions still persist immediately. The credential-spray path also no longer writes each escalating finding twice.
- Scan job findings now persist in batches instead of one write per finding, are capped per job with truncation surfaced in the job record, and retention bounds the total stored finding volume rather than only the job count.
- Fixed a YARA worker that failed to compile rules at startup staying silently dead until it happened to crash: reloads now rebuild the scanner, the failure raises a critical finding, and a failed reload no longer records the rule update as applied.
- Fixed oversized payloads (around 12MB and up) silently scanning as clean in worker mode: scan transport errors are now distinct from clean results, mail scanning fails closed, and finding re-checks no longer auto-resolve on a failed scan.
- Fixed a YARA worker that fails to start at boot leaving the daemon without YARA for its whole lifetime: startup now retries with backoff and raises a critical finding while the worker stays down.
- Fixed one corrupt signature file silently disabling all signature scanning: the remaining files still load, each skipped file is logged, and starting with zero rules is reported loudly instead of ignored.
- Web server detection now probes for the LiteSpeed binary and can be refreshed at runtime, so a daemon that starts before LiteSpeed no longer pins Apache paths for its whole lifetime.
- Fixed spool header parsing dropping headers of 1000 bytes or more, whose length prefix is wider than three digits.
- Fixed the email antivirus MIME parser not understanding the real Exim spool header format, which left headers undetected and the whole scanning pipeline inert against real mail. Single-part attachments now decode correctly instead of failing on the spool marker line.
- Fixed the mail spool scanner deadlocking all scan workers, and with them Exim delivery, by re-scanning its own reads of the message body. Messages whose header file has not been written yet at reception time are now allowed silently instead of warned about or deferred.
- Fixed database auto-response block findings that never actually blocked: attacker session IPs found on compromised WordPress sites now go through the real auto-block path, and reputation alerts for those IPs are no longer wrongly suppressed by a block that never happened.
- Fixed the WordPress option auto-clean corrupting values that contain newlines or serialized data: text read from the database is now unescaped before the backup copy and the cleaned value are written back.
- Fixed stale admin password-change log entries suppressing alerts for fresh unexplained shadow file edits: only events newer than the file's last recorded change can explain a modification now.
- The outbound phishing mail scan now requires at least two independent indicators before alerting, no longer treats PHPMailer or base64 encoding as suspicious by themselves, and decodes base64 HTML bodies to scan the real content.
- Fixed the file index baseline never recovering after a large legitimate shrink, which silently disabled new-file detection until manual cleanup. The guard against mass-deletion floods still holds; a shrink that persists across several scans now becomes the new baseline automatically.
- Fixed new files dropped in nested subdirectories evading the file index between full scans, because only the top directory's modification time was checked.
- Fixed several finding types never being purged after their condition cleared, leaving stale alerts such as ASN crawl criticals pinned forever. A drift test now fails the build when a new finding type is emitted without a matching purge entry.
- Fixed temporary auto-blocks marking the source IP as a permanent local threat, which re-flagged and re-blocked the address forever after the block expired. Leftover entries from old auto-blocks are now ignored immediately and cleaned up automatically; operator-added blocks are preserved.
- Fixed the firewall apply-confirmed safety window not surviving a daemon restart: an unconfirmed ruleset whose deadline passed while the daemon was down is now rolled back at startup, and a still-open window is re-armed for the remaining time. The confirm deadline is recorded before the ruleset is applied, and overlapping apply attempts are rejected so one window cannot corrupt another window's rollback files.
- Fixed a gap where crafted IPv6 traffic could bypass blocks, country blocking, and rate limits on the web ports by colliding with the Cloudflare IPv4 allow list.
- Fixed permanent firewall blocks silently expiring from the kernel after 24 hours while still shown as blocked. Temporary blocks keep their configured expiry, and existing installs converge on the next daemon restart.
- Fixed the IP reputation cache rewriting every cached entry to the state database each scan cycle, which undid expiry cleanup and grew the database without bound. Saves now persist changes and removals in one write.
- The rspamd threat-intel score no longer counts delivered mail, greylisting, or temporary deferrals as abuse, which could auto-block legitimate mail servers that simply sent regularly. It now treats deferrals as neutral and counts quarantine/discard spam verdicts, so mixed histories do not understate recent spam actions.
- CSM's ModSecurity virtual patches are now kept in a marker-delimited section of the shared user rules file, and deploys rewrite only exact CSM marker blocks while preserving operator content and the override include. Previously a redeploy could overwrite the whole file and silently destroy operator-maintained rules.
- A check that hits its per-scan timeout no longer purges the findings it reported in earlier cycles, and throttled checks keep their retry timing without losing stamps across clean shutdowns. Concurrent scans also no longer start the same throttled check before the first run finishes.
- A failed threat-feed download no longer wipes that feed's previously loaded IPs and CIDR ranges, and a cycle where every feed fails now retries next cycle instead of serving no feed data for up to 20 hours. Feed CIDR ranges are also cached to disk now, so they survive a daemon restart.
- Threat-feed IPs shared by multiple feeds now stay loaded when one feed later drops or fails to refresh that address.
- csm backup no longer captures the runtime lock file, and csm restore now refuses to run while the daemon is running or starting. Restoring over live state corrupted both the running daemon's state and the restored copy.
- Blocked-IP alert suppression now compares canonical source addresses instead of substrings, so unrelated look-alike IPs stay visible and already-blocked IPv6 sources suppress correctly even when written in compressed form. Findings without any usable source address are never suppressed.
- WordPress plugin checks now launch wp-cli with runuser instead of su, so under the hardened service unit they no longer flood the journal with read-only lastlog errors and no longer record CSM's internal scans as user logins.

## [3.22.1] - 2026-06-28

### Changed

- Updated dependencies to current releases: go-redis 9.20.0 to 9.21.0, bbolt 1.4.3 to 1.5.0, and the CI actions/checkout (v6 to v7) and actions/setup-go (v6.4.0 to v6.5.0) GitHub Actions.

### Fixed

- Clearing a bloated account error log from the Performance page works again, and malware quarantine can write under user home directories again; the hardened service unit had inadvertently made /home read-only for the daemon.

## [3.22.0] - 2026-06-28

### Added

- The /metrics endpoint now exposes Go runtime memory and goroutine stats (heap in use, idle, released, GC target, goroutine count) so operators can watch the daemon's memory over time and tell live growth from GC headroom. A new opt-in loopback-only pprof endpoint (`debug.pprof_listen`) lets an operator capture heap and goroutine profiles over an SSH tunnel for leak diagnosis.
- Per-IP SYN, connection-rate, and UDP flood limiting now also covers IPv6 traffic, aggregated per /64 so a source rotating addresses within its block cannot slip past the limit. Concurrent-connection limiting stays IPv4-only.
- Mail brute-force alerts now name the mailboxes the source was hitting, with per-mailbox failure counts and a count of attempts that named no mailbox, so operators can tell a real attack on a live mailbox from dictionary noise without opening the mail log.
- New `http_asn_crawl` detector flags a single-ASN distributed crawl of uncacheable URLs that saturates an account's PHP worker pool, and surgically tempbans the offending subnets only when saturation is confirmed (reverse-proxy/CDN safe).
- Operators can now declare DoS-exempt ranges that bypass per-IP connection rate and concurrent limit meters plus mail-port flood meters, and are skipped when auto-blocking subnets; known Google and Microsoft mail-provider ranges are exempt by default, so carrier CGNAT pools and shared mail-provider IPs no longer trigger false-positive throttling or subnet blocks. Individual manual blocks and SYN/UDP flood protection stay in force.
- The status snapshot now reports firewall enabled/managed state and live block counts, so monitoring can detect when the firewall is configured on but the daemon is not actually managing it.

### Changed

- Upgraded the bundled YARA-X malware-scanning engine from 1.17 to 1.19.

### Fixed

- The opt-in pprof listener now handles failed diagnostic binds without leaving background shutdown work behind.
- The challenge port-gate no longer floods the log with revoke errors: it stops trying to revoke gate access for IPs that were never gated (such as verified crawlers that bypass the gate), and treats an already-expired gate entry as already removed.
- The daemon now automatically compacts its bbolt state database at startup when the file has grown large and is mostly free pages, reclaiming on-disk slack that bbolt never frees on its own, so the state file no longer balloons over time without a manual `csm store compact`. Compaction is non-destructive and on by default (disable with `retention.compact_min_size_mb: 0`); the separate, destructive retention sweeps remain opt-in.
- Startup compaction now waits for the daemon instance guard and honors the documented disable setting from main and drop-in configs.
- The hardened systemd unit now supports legacy state paths and cPanel forward-guard rebuilds without leaving the daemon stuck on read-only system paths.
- The mail-queue spam-outbreak check works again under the hardened systemd unit; previously the queue probe could not run, so the check silently reported an empty queue and a flood from a compromised account could go unnoticed.
- The per-IP connection-rate, concurrent-connection, SYN-flood, and UDP-flood meters now match IPv4 sources only, so IPv6 traffic no longer writes mis-keyed bogus entries into the IPv4 rate-limit tracking sets. Per-IP metering of IPv6 sources for these rules is not yet implemented.
- PHP Shield now reports an inactive protection gap when it is enabled but not installed, marks component health unhealthy, and stops retrying a dead event log forever.
- PHP Shield enable/disable now re-sign the saved config after toggling protection, so following the daemon repair hint does not make the next restart fail integrity checks.
- ModSecurity advisory-only confidence findings no longer feed any firewall path, low-confidence burst notices do not repeat until the active window drains, and sustained ModSecurity attackers can refresh a temporary ban after the block window expires.
- The package mirror no longer deletes the signed YARA Forge rule subtree when publishing a release, so operators relying on the mirror keep receiving signed YARA Forge rule updates between weekly refreshes.
- ModSecurity escalation to a firewall ban is now confidence-gated: a burst of low-confidence policy/anomaly denies (e.g. COMODO content-type or anomaly-score rules from an unusual but legitimate checkout) no longer auto-bans the customer's IP, while real attacks (which trip specific attack rules) still escalate; a deliberate low-confidence-only flood is still banned at the `thresholds.modsec_low_confidence_escalation_hits` backstop (default 30).
- Firewall apply no longer fails on hosts with large blocklists: the engine now requests a larger netlink socket buffer, so applying a full ruleset does not overflow the kernel buffer and leave the firewall unmanaged.
- Automated firewall actions no longer log repeated failed-block warnings when they decline to block the server's own interface addresses or operator infra IPs; those are treated as expected no-ops. The triggering finding is still recorded, so suspicious activity attributed to a protected address (such as a compromised site pivoting through the server IP) is still surfaced.
- XML-RPC abuse blocking is now tunable via config and Settings (`thresholds.xmlrpc_threshold`, set 0 to disable) and its default was raised, so busy WordPress sites using Jetpack, the mobile app, or WooCommerce are no longer auto-blocked for legitimate xmlrpc.php traffic.
- A visitor whose User-Agent claims to be a search-engine bot but fails reverse-DNS is now blocked only after sustained activity (the `http_ua_spoof` threshold), so a legitimate residential or mobile client that sends a bot-like User-Agent once is not auto-blocked on first contact.
- Auto-response dry-run now also suppresses subnet blocks from the spray and netblock-escalation paths, matching how it already suppresses individual IP blocks.
- Mail brute-force target summaries now escape unusual mailbox text and cap each name, so crafted login names cannot distort alert details.

### Notes

- Behind a reverse proxy/CDN, set `web_server.trusted_proxies` so `http_asn_crawl` attributes the real client; without it CDN-fronted traffic is treated as the proxy and not flagged.

## [3.21.0] - 2026-06-23

### Added

- WebUI admins can enqueue and cancel full-scan jobs via `POST /api/v1/scan-jobs` and `POST /api/v1/scan-jobs/{id}/cancel` (admin auth + CSRF), sharing the daemon's single-job queue.
- WebUI exposes read-only `/api/v1/scan-jobs` endpoints (list, detail, paginated findings) for full-scan job reports.
- Operators can run an uncapped, report-only full scan of a single account (`csm scan <user> --full`) that checks every file, including ones the normal scan skips for speed, and review the results later with `--status` and `--report`.
- `csm scan --all --full` runs an uncapped report-only scan across every cPanel account under one job, with per-account progress and error isolation.
- `csm scan <user> --full --quarantine` now quarantines eligible malware/webshell file findings (report-only by default), recording per-finding remediation status; process-kill, DB, and firewall actions are never triggered.
- Periodic content scans now also sweep a small rolling slice of each account's full web tree every cycle (on by default), so dormant files the fast scan skips for speed are eventually content-scanned without a manual full scan.
- Block digest email and webhook now break blocks down by category and call out ModSecurity (WAF) blocks in a dedicated section.
- The block digest's ModSecurity section now names the customer domains and request paths each blocked IP was hitting, drawn from events already on record so no extra log scanning runs.
- The ModSecurity dashboard can now filter blocks and events by time range, minimum severity, and source country, and shows the source country of each event.

### Fixed

- Integration CI now fails early if built amd64 packages are missing or duplicated, instead of silently picking an arbitrary artifact.
- Block digest now counts ModSecurity escalations and high-volume WAF blocks as attacker traffic instead of flagging them as customer-risk false positives.
- Mail brute-force auto-blocks are now flagged as a possible false positive when the same source has recent successful mail logins for other mailboxes, so a stale saved password is easier to tell apart from a real attack.
- Credential-spray grouping now includes PAM login-failure sprays from one source and counts the targeted accounts reported by the PAM listener. Operators who enabled spray suppression without a custom detector list now get the intended PAM coverage.
- Docs: corrected reference drift across the CLI, API, configuration, and detection pages so they match shipped behaviour, and fixed non-ASCII style violations in the docs.

## [3.20.0] - 2026-06-22

### Added

- Added an optional per-country block digest: when CSM auto-blocks IPs it reports those from your customers' countries (split likely-customer vs attacker) on a schedule or as live alerts, so a false positive no longer silently cuts off visitors. Off by default; configure under alerts or in Settings.
- A successful FTP login from a source that just failed repeated login attempts is now flagged as a likely cracked credential, naming the affected account, so a guessed password pages loudly instead of hiding among routine login notices.
- Re-check now also covers content findings (suspicious/obfuscated PHP, signature and YARA matches) by re-running the classifier on the file's current bytes; it clears a still-present file only when its bytes are unchanged since detection and current logic no longer flags it, so a file edited after detection is never auto-cleared.
- Stale content findings now clear automatically on daemon start after a detection-logic update (heuristic, signature, or YARA), when the flagged file is unchanged since detection and current logic no longer flags it, so operators no longer have to manually clear false positives left behind by improved detection.

### Fixed

- IP reputation no longer auto-blocks an address that is actively and successfully logging in to mail, so a customer on an ISP-recycled IP that turns up in a public threat feed is not locked out of webmail; unauthenticated threat IPs are still blocked.
- Mail brute-force no longer auto-blocks an established good source that fails a confined set of mailboxes (typically a stale saved password on one device); it is reported in alerts and the email workbench instead, while password spraying and confirmed account compromise still block.
- Mail brute-force good-source standing now persists across daemon restarts and loads before mail logs resume, so a restart or upgrade no longer briefly re-blocks established customers while their standing rebuilds.
- Email alerts now use a bounded SMTP send with a hard timeout, so a stuck or slow mail server can no longer hang alert delivery or hold up daemon shutdown.
- FTP login alerts no longer page on loopback (cPanel's own internal transfers) or on ordinary customer logins; routine logins are now recorded at audit level instead of high severity.
- FTP success-after-brute alerts now use only failures still inside the configured window, ignore loopback variants, and do not trigger incident-level auto-blocks by themselves.
- The firewall integrity check no longer falsely reports the ruleset as modified outside CSM when an IPv6 address is blocked or unblocked.
- File-index content findings (obfuscated/suspicious PHP in uploads, languages, upgrade) now carry a content fingerprint at detection time, so Re-check and the stale-content sweep can auto-clear them when the file is unchanged and the classifier no longer flags it.
- Startup stale-content cleanup now drains during daemon shutdown, so state is not closed while findings are still being cleared.
- Content Re-check now uses the stored finding fingerprint, keeps realtime heuristic, location, or name-based malware findings active while the file remains present, and no longer clears a finding when the live file cannot be verified consistently.
- The dashboard header now counts every active incident instead of the first page, so it no longer reports a handful when hundreds are open or contained.
- The dashboard health badge now reflects active critical and high incidents, not just whether the daemon is running, so it stops showing "Healthy" while critical incidents are open or contained.
- The dashboard health badge now also follows degraded daemon state, so detached watchers or store failures no longer appear healthy.
- Outdated WordPress plugin scans now collapse cPanel document-root symlinks before scanning, avoiding duplicate install findings.
- FTP brute-force detection now follows pure-ftpd logs across scan cycles and restarts, including IPv6 peer tokens, so slow same-source attacks are counted reliably on busy system logs.
- ModSecurity LiteSpeed handling no longer turns pass-action rule hits into auto-blocks during temporary rule-load gaps, while keeping the last known rule actions when refreshes briefly see no rules.
- Late platform override attempts are now ignored consistently by fresh re-probes, so background refreshes stay aligned with the startup platform view.

## [3.19.0] - 2026-06-20

### Added

- Security Findings now have a "Re-check" action that re-evaluates a finding against the live filesystem and clears it if the condition is gone, so an operator who fixed something by hand can confirm it without waiting for the next scan. It appears only on findings CSM can re-evaluate (file-permission, webshell/malware, phishing, `.htaccess`, Exim spool and crontab); event findings such as brute force do not show it.
- Re-check now also covers outdated-WordPress-plugin findings: it re-runs `wp-cli` for that one site and clears the finding when no active plugin is outdated anymore, so an operator who just updated plugins gets immediate confirmation.
- Re-check now also covers WordPress core-integrity findings: it re-runs `wp core verify-checksums` for that install and clears the finding when the install is gone or checksum verification is clean.
- Re-check now also covers unauthorized-UID-0-account and SUID-binary findings: it re-reads `/etc/passwd` (cleared when the account is gone or no longer UID 0) and re-stats the binary (cleared when removed or no longer setuid).
- Re-check now also covers modified-system-binary findings: it re-runs `rpm -V` (RPM) or `debsums` / `dpkg --verify` (Debian) for the package and clears the finding when that file is no longer reported as modified.
- Package-integrity re-checks now leave findings in place when package-manager output cannot be parsed.
- Re-check now also covers WordPress database-content findings (injected options, siteurl/home hijack, injected posts, cloaked spam): it re-queries the affected row as root and clears the finding only when the row is gone or no longer matches the detector; any database error leaves it in place.
- Re-check now also covers Drupal, Joomla, Magento, and OpenCart database-injection findings (settings/config and content/article rows): it re-reads the one flagged row and clears the finding only when it is gone or no longer matches the malware classifier.
- Re-check now also covers malicious/unexpected database triggers, events, procedures and functions, and the backdoor magic-token user finding: it re-reads the object's current definition from the database and clears the finding only when the object is gone (or, for malicious objects, no longer matches a malware pattern).
- Re-check now also covers database administrator-account findings (WordPress rogue admin and disposable-email admin, and Drupal/Joomla/Magento/OpenCart admin accounts): it re-queries the flagged account and clears the finding only when that account is gone or no longer privileged.

### Changed

- Updated the Sentry Go SDK to 0.47.0.

### Fixed

- Database-content Re-check now ignores malformed account markers in finding text and refuses invalid account names before locating an install.
- Mail brute-force trust handling now stays conservative when login context is incomplete or a success follows repeated failures, so attacker activity is not hidden by the legitimate-sender exception.
- Mail brute-force and account-compromise alerts no longer fire when the source IP is already an established legitimate sender for that mailbox, so a second device with a misconfigured password (for example IMAP failing while POP3 keeps working) no longer gets the customer's own IP auto-blocked.
- Database-object Re-check now keeps multiline malicious bodies classified consistently and checks the exact WordPress user row for backdoor-token user findings.
- WordPress administrator-account Re-check now checks the matching WordPress install instead of clearing a finding from another install under the same account.
- WordPress database-content Re-check now handles multisite and shared-database installs without clearing a finding from the wrong WordPress tables.
- UID 0 account re-check now keeps findings active when another matching account record is still privileged, and refuses account names that cannot map safely to the account database.
- Automated fix and re-check now use stored finding paths exactly, avoiding false clears on unusual filenames.
- Findings Re-check now sends stored finding details from the table, so WordPress re-checks can locate the affected install.
- Outdated-plugin Re-check now validates the WordPress install path and site owner before running `wp-cli`, and keeps the finding active when the re-scan cannot be trusted.
- Findings re-check now keeps path-presence findings active when the flagged path still exists, and refuses ambiguous filesystem targets instead of clearing them when the path cannot be verified safely.
- Crontab findings now carry their target path, so Re-check can validate them from the Findings page.
- Applying the automated permission fix for a world- or group-writable PHP finding now recognises a file an operator already corrected and clears the finding instead of failing, and explains read-only-mount failures (e.g. backup snapshots) instead of surfacing a raw "read-only file system" error.

## [3.18.0] - 2026-06-19

### Added

- CSM now probes the cPanel mail authentication backend and pauses mail brute-force auto-block while it is down. Operators can opt in to a rate-limited mail service restart after a sustained outage.

### Fixed

- Mail auth recovery now keeps auth-failure parsing responsive while probes or restarts are running, validates restart settings, and marks those settings as restart-required.
- The Inspect IP firewall check now reports cPHulk as active for brute-force temporary bans, not only for entries on cPHulk's permanent blacklist, and avoids matching unrelated IP text.
- Mail brute-force and account-compromise auto-blocking now weighs successful logins against failures before acting, so a busy office that shares one address across many mailboxes is not locked out because a single device kept retrying a stale saved password. Genuine attacks, which fail far more than they succeed, are still blocked.
- Mail-auth success-ratio checks now require matching mailbox context before suppressing a block. Account-compromise detection also drops expired failure history, and diagnostics count compromise findings emitted from successful logins.
- Mail brute-force and subnet auto-blocking pause, and an operator warning is raised, when the mail authentication backend is failing. A backend outage makes every login fail regardless of password, so without this it would lock out legitimate users en masse. Detection resumes automatically once the backend recovers.
- Mail auth backend outage detection now validates backend-error evidence more narrowly and bounds outage state under log floods.

## [3.17.0] - 2026-06-18

### Added

- A new `mailbox_bruteforce` incident kind covers failed mailbox logins, mail brute-force bursts, and SMTP probes. These are keyed on the attacker IP and auto-close after 24h; post-authentication abuse still classifies as `mailbox_takeover`.

### Changed

- Inbound web attacks now open a `web_attack` incident even when the request names the targeted site or account. A blocked ModSecurity hit or scanner probe records the victim vhost, which is the attack target, not evidence the account is compromised, so these are keyed on the attacker IP and no longer inflate the `web_account_compromise` count or its 7-day review window. Genuine compromise is still recognised by on-disk and behavioural signals.

### Fixed

- A user crontab that contains only CSM's own WP-Cron entries no longer raises a host-integrity alert after a daemon restart; recognition is content-based, so a crontab with any other cron entry is still flagged and attacker persistence is unaffected.
- Auto-generated WordPress translation cache files no longer raise a sensitive-directory alert; recognition is based on their data-only content, so any such file carrying executable code is still flagged.
- WordPress notification mail, such as comment-moderation messages sent to a site's own admins, no longer triggers a PHP mail-relay alert just because one visitor IP drives several mailer scripts; the relay check now also weighs how many distinct recipients are reached, so genuine outbound spam to many addresses still fires.
- Several malware signatures no longer flag legitimate WordPress security and backup plugin code that only references attack keywords; each rule now requires the malicious behavior itself, and detection of the real threats is preserved.
- Web UI bulk select-all now selects only the rows on the current page, so a permanent delete of quarantined files, ModSecurity blocks, or email quarantine messages no longer also removes rows hidden on other pages or by an active filter.
- Bulk action bars now refresh after table pagination, search, or filters change, so hidden checked rows cannot keep stale actions active.
- Web UI keeps quarantine, ModSecurity, and verified-bot timestamps in the operator's local time instead of raw UTC and sorts those columns chronologically; quarantine rows are also no longer blanked by the periodic relative-time refresh.
- Dashboard summary line counts critical and high findings from the last 24 hours, matching its "(24h)" label and the posture cards, instead of all-time active totals.
- Findings page no longer shows a false "New findings detected" banner; auto-refresh now compares against the same deduplicated source the table renders from, so it only appears on a real change.
- Findings refresh now catches severity-only changes and keeps merged IP reputation source ordering stable between polls.
- Web UI Size columns (quarantine, cleanup, database backups, rules) now sort by actual byte count and the findings Severity column sorts by severity, instead of by their formatted display text.
- Web UI size formatting now leaves missing or invalid byte counts blank instead of rendering `null` or `NaN` text.
- Email findings show the account and source IP from structured finding data, so IPv6 attacker addresses are no longer blank and the columns no longer break when a message is reworded.
- Email findings now keep account and IP values for legacy mail-log rows and bare cPanel auth users when stored rows predate structured fields.
- Hardening score no longer renders a NaN percentage, derives missing score data from result rows, and uses a neutral bar when no checks ran. The performance Redis card no longer paints a healthy unlimited-maxmemory Redis red.
- Dark theme now resolves all surface colors from one set of tokens instead of two slightly different palettes. The top bar keeps the card surface, and the connection-status pill uses dark-theme colors instead of light fallbacks.
- Incident list now shows CRITICAL as a red badge instead of a gray one, and modsec event severities use the same severity colors as the rest of the UI.
- Severity badges now keep a neutral color for missing or unexpected values instead of showing them as warnings or unstyled badges.
- Web UI confirmation and input dialogs now use the app's themed modal everywhere, including the firewall rollback timer prompt, instead of unstyled native browser dialogs; quarantine and cleanup file previews open in the shared detail panel.
- Settings dialogs no longer stack or apply stale actions when browser history changes or firewall rollback controls are triggered again while a modal is open.
- Web UI now shows a contextual hardening load error and a single inline firewall challenge load error without repeated poll toasts or stale challenge data.
- Web UI findings and threat pages refresh in place after a fix, dismiss, suppress, or bulk action instead of reloading the whole page, so filters, search, and scroll position survive a long triage session.
- Web UI in-place refreshes now ignore stale overlapping responses and clear empty finding or attacker views without leaving old selections, exports, or charts behind. Load-failure retry buttons keep using a full page refresh where the page shell is replaced.
- Web UI sticky elements (findings filter header, settings save footer, bulk-action bar) now stay pinned while scrolling; the page's horizontal-overflow guard no longer turned the page into a scroll container that disabled them.
- Web UI outbound-abuse "Block 24h" and ModSec escalation-exclusion removal now ask for confirmation, ignore repeat clicks, and keep only one modal action active. A bulk threat block or whitelist offers a 30-second undo.
- Web UI settings now lock the whole section form while a save is in flight, so edits made during the round-trip are no longer lost and a second submit cannot fire; the header badge no longer says "Applies live" while a restart notice is active, and a single restart notice shows instead of two.
- Web UI ModSecurity rule changes now show the real error when an escalation toggle or apply fails, instead of a doubled "Error: Error:" prefix, and a failed apply reverts staged toggles before rebuilding from the live ruleset.
- Web UI dashboard now stops refresh loops before restarting them after tab visibility changes, so switching tabs cannot build up a fetch storm; failed dashboard and firewall panel refreshes now show a single inline error instead of also repeating a toast every poll.
- Web UI now rejects malformed IPv6 addresses (such as ":::::") instead of accepting any string of colons, validates a subnet's CIDR prefix before submitting a block, keeps malformed colon queries out of incident IP search, and parses all timestamps through one shared helper.
- Web UI audit log export now records the absolute timestamp instead of the relative "3h ago" text when available, shows the absolute time on hover, and audit rows are no longer blanked by the periodic relative-time refresh.
- Web UI confirm dialog now announces as a labelled modal to screen readers, the command palette and shortcuts help share the detail panel's focus trap, the shortcuts help follows the light/dark theme, and the login button locks after the first submit.
- Web UI command palette result rows now stay out of the Tab order, so Tab remains trapped on the search field and Enter cannot activate a different result than the highlighted one.

## [3.16.1] - 2026-06-15

### Changed

- Inbound web attacks and remote-IP reputation hits from an external IP (ModSecurity rule hits, rule escalation, high local threat score — all with no account attribution) now open a dedicated `web_attack` incident kind that auto-closes after 24h, instead of being labelled `web_account_compromise` and held for 7 days. Account-attributed web findings still classify as `web_account_compromise`, so the compromise count and its longer review window are no longer inflated by anonymous probes.

### Fixed

- The URL scanner-profile detector no longer counts 404/403 responses on static display assets (images, stylesheets, scripts, fonts, media) toward its probe profile, so a site whose CDN or image paths are missing no longer makes ordinary visitors look like URL scanners and get challenged into a timeout block; archives, code, configs, dumps, and extensionless paths still count.

## [3.16.0] - 2026-06-15

### Added

- Anthropic's ClaudeBot is now recognized out of the box by its published IP ranges (Anthropic now ships a machine-readable feed and documents address-based verification, not reverse DNS). The ranges ship as a snapshot and refresh on the same schedule as the other AI crawlers.
- The Verified Bots page now shows the built-in AI-crawler ranges read-only: whether auto-update is on, the refresh interval, the last refresh time, and how many IP prefixes are loaded per crawler.
- A new `csm update-bot-ranges` command refreshes the built-in AI-crawler IP ranges from the vendor feeds on demand and tells the running daemon to apply them without a restart, mirroring `csm update-geoip`. The auto-updater now also exports metrics (refresh success/failure, prefix counts per crawler, and the last successful refresh time).
- A new URL scanner-profile detector flags source IPs whose traffic is almost entirely 404/403 responses spread across many distinct paths, the shape of random-URL probing for downloadable files and exposed backups. Disabled by default; volume, error-rate, and path-breadth gates keep dead bookmarks, broken assets, and site migrations from triggering it, tuning values are validated, settings are editable from the web UI, and flagged IPs feed auto-block and the distributed rollup without counting unrelated vhost misses.
- IPs flagged by the URL scanner-profile detector are routed to the proof-of-work challenge by default so a real visitor behind a shared IP can clear themselves, with a switch to hard-block instead available in both the config file and the web UI; when the challenge subsystem is disabled both settings block. Panels can feature-detect the detector via the capabilities endpoint.
- New metrics make challenge activity graphable: how many IPs each detector routes to the proof-of-work challenge, and how many challenge timeouts escalate to a hard block versus a no-op, so the URL-scanner and other challenge-based protections have visibility over time.
- The web UI now surfaces challenge activity directly: a Challenges panel on the Firewall page and a card on the dashboard show how many IPs are pending the proof-of-work challenge, how many timed out into hard blocks, the routes per detector since restart, and the most recent routes.
- Challenge activity can now be feature-detected through the capabilities endpoint.
- Operators can extend the verified-bot allowlist from config: list a crawler's UA substrings plus either reverse-DNS suffixes or published IP ranges, and CSM confirms it (forward-confirmed reverse DNS, or address membership for AI agents like PerplexityBot/GPTBot/ClaudeBot that have no crawler reverse DNS) before trusting it, so legitimate crawlers stop tripping the URL scanner-profile alert without a code change. Shared-hosting suffixes and over-broad or non-public IP ranges are rejected so the list cannot become a bypass, and changes apply on reload.
- GPTBot, ChatGPT-User, OAI-SearchBot and PerplexityBot are now recognized out of the box by their published IP ranges (they have no crawler reverse DNS), so they are no longer mistaken for scanners with no configuration. The ranges ship as a snapshot and refresh automatically from the vendors on a schedule; the fetched data is validated the same way operator entries are, so a bad feed cannot widen the allowlist. Can be disabled.
- The verified-bot allowlist now has a web UI editor (Verified Bots page) to add, edit, and remove crawlers and AI agents, with the same validation as the config file; saved changes apply live without a restart.

### Fixed

- An auto-block no longer overrides the allowlist: an IP on the operator full-IP/port allowlist or in a verified-bot range is left out of the blocked set instead of being re-blocked behind it. An explicit operator deny still takes precedence.
- A crawler that identifies by reverse DNS (no published IP range) is no longer hard-blocked during the brief window before its identity is confirmed: heavy crawling from a claimed bot is sent to the proof-of-work challenge instead, so a real crawler clears itself on the next pass while a spoofed crawler UA cannot. Matters most right after an upgrade, when the verification cache is empty. A spoofer is still hard-blocked once verification fails.
- Verified-bot config is now normalized before DNS checks, and unsafe entries are rejected during every config load path.
- The verified-bot IP-range validator rejects two more non-public blocks (the "this network" 0.0.0.0/8 range and the deprecated 6to4 anycast range), so neither an operator entry nor a vendor feed can slip them into the crawler allowlist.
- Challenge routing now also runs before auto-blocking on the scheduled-scan path, and a pending challenge no longer shields an IP from blocks owed to confirmed-threat or block-mode findings.
- Challenge-eligible findings now fall back to hard blocks when challenge routing is disabled, even if a stale pending-challenge entry is still present.
- IPs routed to the proof-of-work challenge no longer linger as stale entries in the findings view; the routing action is treated as a one-shot event like auto-block rather than durable state.
- The suspicious PHP content detector no longer flags assert() calls whose argument provably evaluates to a boolean or number (file-existence checks, comparisons, arithmetic, shifts, logical expressions), fixing a false positive on a legitimate WordPress plugin. Multiline code-eval calls stay correlated to their full argument list, arguments that can carry an attacker-built string stay flagged, and builtin names are not trusted in files that could redefine them via namespaces or function aliases.
- Deeply wrapped PHP assertion arguments are now scanned in one pass, so crafted files cannot stall scanning and normal boolean checks do not become false positives just because they use extra grouping.
- HTTP scanner, request-flood, and UA-spoof source IPs now build local attack reputation and threat score history instead of being forgotten between scans.
- SERanking's backlink crawler is now recognized as a verified bot via forward-confirmed reverse DNS, so its heavy 404 crawling no longer raises a false URL scanner-profile alert while a spoofed crawler UA from an unrelated host is still flagged.
- The distributed HTTP-attack rollup now also catches scanners that spread their probes thin across many vhosts, so a coordinated botnet converging on shared sites is no longer missed just because no single vhost crossed the per-IP request threshold.
- The challenge-timeout escalator log no longer claims a fresh hard block when the IP was already blocked or the block was a dry-run, so incident review is not misled.
- Saving the scheduled-scan disabled-checks list now rejects unknown check names instead of accepting them silently, so a typo no longer leaves a check running while it appears disabled. Existing entries that use a runner ID or extra whitespace still validate.
- Restarting the daemon from the web Settings page no longer reports a spurious "Restart failed" or reloads against the still-running old daemon. The page now waits for the restarted daemon before refreshing, handles upgrades from a daemon that does not return a start marker, and reports when a restart was not observed.
- The firewall page now chunks GeoIP batch lookups, so hosts with more than 500 blocked IPs no longer get an HTTP 400 followed by a per-IP request flood that tripped the API rate limit with 429 errors.
- WP-Cron system crons installed by the remediation are now staggered per account instead of all firing in the same second, run under a lock so slow passes cannot overlap, and default to every 15 minutes instead of 5. Existing CSM-installed cron lines are upgraded automatically at daemon start; tampered or unsafe marker content is rejected and customer-authored cron entries are never touched.
- Realtime alerts for executables created in temp directories are demoted to warnings when the file is root-owned and the writing process descends from an active package-manager transaction, so kernel updates no longer page operators with hundreds of criticals. Demoted findings stay visible with an annotation; nothing is suppressed.
- DNS zone-change monitoring now separates routine cPanel edits (serial bumps, AutoSSL and DKIM records, owner address repoints) from tampering, so it no longer alerts on every customer DNS change. Delegation or mail-record changes, anything edited outside cPanel, and zones lacking trusted cPanel provenance still raise an alert, and records are canonicalized first so crafted syntax cannot hide a change.

## [3.15.0] - 2026-06-11

### Added

- A new metric counts failed alert deliveries (email, webhook, phpanel) so operators can see when findings are detected but not reaching anyone, instead of the daemon appearing healthy while alerts silently fail.

### Fixed

- Failed alert delivery metrics are now recorded once when a channel send fails, so repeated error handling cannot inflate the count.
- Email quarantine actions now reject empty, dot, parent, and path-like message IDs before touching disk, so a malformed ID cannot resolve to the quarantine root or its parent.
- The web UI CSRF check now fails closed without an active admin credential and no longer derives tokens from disabled legacy credentials.
- Country blocking now covers IPv6 as well as IPv4: the geo database fetches IPv6 ranges and the firewall drops blocked-country traffic on both families, closing a path where an attacker on an IPv6 address from a blocked country was never stopped.
- Firewall source-address lists now match only their own packet family, so dual-stack traffic is no longer checked against the wrong list.
- The web UI no longer serves a browsable listing of its static asset directory; individual assets still load (the login page needs them) but the file set can no longer be enumerated.
- IPv4 addresses reported in IPv4-mapped IPv6 form are now canonicalized consistently across challenge handling and firewall state, so dual-stack traffic keeps the same block and allow decisions after restarts and cleanup.
- Filtering the history view by an older date range is now much faster on hosts with large history, because the query seeks to the end of the range instead of scanning back over every newer entry first.
- Filtered history requests now return older matching rows even when many newer rows exist, instead of reporting only the recent scan window.
- Mail-provider deferral text captured from remote servers is now normalized and truncated on a character boundary, so invalid bytes or a multi-byte character at the limit can no longer be stored as corrupt text.
- A failed verdict-callback now reports the IP through the normal error path instead of writing it to standard error.
- Database spam cleanup now avoids repeated validation setup, speeding up remediation on large infected databases.
- Config drop-in fragments that repeat a list entry already in the main config (infra IPs, blocklists, trusted countries, disabled checks) no longer produce duplicates after merge; lists of structured entries such as tokens are still appended unchanged.
- PHP content analysis now scans a much larger head window plus the tail of large files, and treats skipped middle content as a hard boundary. Malicious payloads can no longer hide behind padding that pushed them past the old fixed read size.
- IP-reputation collection now reads SSH, web, and mail file logs through platform detection and configured mail log paths, so it works on Ubuntu/Nginx and other supported hosts. WHM access parsing and the webmail/WHM-API brute-force checks stay cPanel-gated, while Exim mainlog parsing still runs when that log exists.
- Webhook alert delivery now drains short reusable responses before closing, so chunked endpoints can keep their connection warm without letting slow bodies stall dispatch.
- Remote YARA rule updates now use durable atomic writes. Forge tier changes keep the previous active tier until the replacement is written, and oversized decompressed rules are rejected.
- The live audit-log AF_ALG listener now caps its partial-line buffer and resets that drop state after log reopen, so a truncated or never-terminated audit record can no longer grow daemon memory without bound or hide the next event after rotation.
- The new-file index scan is now interruptible and no longer promotes a partial file list as its baseline when a scan is cut short, which would have made every un-walked file look newly created on the next cycle.
- The YARA worker restart delay now grows for repeated quick crashes, resets after the worker stays healthy, and no longer reports a dead child as running during restart backoff.
- Email attachment extraction now caps how deeply multipart wrappers can nest: a crafted message can no longer hide attachments under unbounded nesting, and over-deep messages route through the existing partial-extraction policy instead of delivering as if they had no attachments.
- Forwarder and mail-filter files that first appear after the initial audit now alert as newly added: the first-sight suppression meant a freshly dropped BEC forwarder was never reported, because the next scan already saw an unchanged hash. Pre-existing files at install time stay quiet, account-scoped scans no longer mark the global audit complete, and an unavailable state store is now reported instead of looking like a clean host.
- Forwarder and mail-filter baselines now wait for complete scans before marking the initial audit done. The mail-filter store-unavailable warning is throttled instead of repeating every cycle.
- Subnet blocks, IP unblocks, and IP allows now persist their state change before touching the kernel, so crashes converge to the operator's last firewall action. Unblocking or allowing an IP whose old kernel block already disappeared now clears stale state instead of forcing repeated retries.
- Expired temporary allows and subnet blocks whose kernel cleanup partially fails are now retried entry by entry instead of wedging the whole cleanup until the daemon restarts.
- Config saves, integrity hash updates, default-config deployment, config migration, and firewall profile restore now write through atomic renames. The legacy config symlink is preserved and adjacent scratch files are left alone.
- The email AV spool watcher no longer leaks scanner workers and file descriptors when its kernel event-loop setup fails: workers now start only after the event loop is ready, so daemon shutdown cannot hang on them.
- The email AV spool watcher now retries restart setup with a fresh instance after setup failures, avoiding reuse of a stopped watcher.
- Log watchers no longer lose unread lines around periodic reopen, replacement-file rotation, or in-place truncate/regrow rotation. Failed reopens also recover cleanly when the log path returns.
- Log watcher startup now falls back to reading the current log after a rotation race instead of keeping a stale position that could skip replacement content.

### Documentation

- Documented the opt-in email forward guard (config, defaults, and which signals actually hold versus log) and the Email page's new Forwarders, Deliverability, and queue-backscatter views.

## [3.14.0] - 2026-06-08

### Added

- The Email Security page has a new Forwarders tab listing every mail forwarder on the host, where it delivers, who owns it, and whether mail also stays in a local mailbox, so operators can see at a glance which accounts relay mail off-server to free providers.
- The Email Security page has a new Deliverability tab showing which mail providers are throttling the server and which sending IPs are affected, with each provider's stated reason, so operators can see why outbound mail is backing up.
- The Email Security Queue tab now breaks down the mail queue into real mail versus null-sender bounce backscatter, with frozen count, oldest age, and the most stuck recipients, so operators can tell a genuine backlog from junk filling the queue.
- The Email Security Queue tab can flush frozen null-sender bounce messages from the mail queue in one click, clearing undeliverable backscatter without touching real mail or messages still being retried.
- New opt-in email forward guard (off by default): on a cPanel host the mail server itself holds spam-bounce and bad-sender forward copies before they relay to an external provider, while the local copy still delivers. Held copies can be released or deleted, and mail keeps flowing if CSM is down since CSM never sits in the live mail path.

### Fixed

- PHP-relay findings now include the relay count and contributing script samples they advertise, so the email page can show which script caused a mail-abuse alert.
- Stopping the daemon (e.g. during an upgrade) is fast again: it cancels an in-flight scan and records queued findings to history instead of running the full auto-response pipeline (firewall blocks, permission fixes, alert delivery) while the service waits to stop. The next startup re-detects anything still outstanding, and the last completed scan results are preserved.
- The attacker-IP database now saves only the records that changed since the last save, instead of rewriting the whole set every save and on shutdown. On hosts tracking tens of thousands of IPs this removes a multi-second CPU spike that was slowing daemon shutdown and briefly stalling attack recording.
- Attack database deletes are now retried if the store is unavailable, a re-added IP is no longer removed by a stale pending delete, and load-time score repairs are saved.
- The Email Security Queue tab no longer reports an empty queue (and the flush-backscatter button no longer does nothing) while the header shows queued, frozen, and stuck messages: the queue parser now accepts the message-id format Exim 4.97+ emits, not just the legacy short form, and handles entries that name the local submitting user before the sender.
- Email phishing remediation now accepts modern Exim message IDs when quarantining spool files, so the fix action does not reject valid Exim 4.97+ messages.
- The Email Security pagination footer ("Showing 1-25 of 250") no longer leaks onto every tab; per-table pagination controls now stay scoped to their own tab pane.
- The Email Security action-groups list now orders groups of the same severity by event count, so the busiest clusters surface at the top instead of just the most recent.
- A single IP that hammers one mailbox with mail or SMTP login failures is now auto-blocked only after a recent high-rate pattern, instead of going unblocked because per-event auth failures were not counted toward the attacker's local reputation score. Slow stale-password retries from a real user stay below the block threshold.
- A domain hitting the cPanel hourly defer/fail limit is no longer reported as a spam outbreak or auto-held on its own, since the same limit trips on inbound junk, full mailboxes, and bounce backscatter. It now surfaces as a deliverability event, and an outgoing-mail hold is applied only when outbound volume confirms a real outbreak, so clearing a false-positive hold no longer gets the account re-held.
- The WP-Cron auto-fix now actually runs during scans when enabled, while leaving suppressed warnings untouched and keeping fixed warnings cleared after restart.
- A corrupt auto-block or alert-suppression state file is now logged instead of being silently discarded, so operators notice when queued blocks, escalation history, or suppression data are lost.
- Reverse-DNS enrichment now caps how many lookups run at once, so a wedged resolver can no longer accumulate stuck background work under a flood of distinct addresses.
- Default ModSecurity no-escalate seeding now writes the rule and completion marker together, so startup retries after a failed seed instead of treating it as done.

## [3.13.1] - 2026-06-07

### Fixed

- The release install/upgrade scripts no longer abort with a false "tampered binary" error on OpenSSL 1.1.1 hosts (EL8/CloudLinux 8) once releases are signed. Signature verification runs on OpenSSL 3.0+, is skipped with a warning where the platform cannot perform it (the SHA-256 checksum is still enforced), and only fails the upgrade on a genuine signature mismatch.
- Release script signature checks no longer misclassify capable OpenSSL hosts as too old, so signed binaries are still verified before install or upgrade.

## [3.13.0] - 2026-06-06

### Added

- WP-Cron findings now have a one-click fix (per-row and bulk) that disables WP-Cron in wp-config.php and installs a per-user system cron to run wp-cron.php, so scheduled tasks keep running. Interval and PHP binary are configurable, and an opt-in auto-response can apply it automatically.
- Groundwork for reporting confirmed-abuse IPs to a central abuse database or a private collector. Reports are minimized to an IP, an abuse class, a count, and timestamps, carrying no account, domain, mailbox, or path data, and are signed so a receiver can authenticate them.
- Durable, bounded outbound spool and HTTPS-only signed delivery for abuse reports, so a down collector or a restart does not drop them.
- Abuse reporting is now wired into the daemon and configurable under `reputation.report` (opt-in, default off): confirmed-abuse findings are reported to the configured targets.
- Signed scored-set consume codec: verifies the Ed25519 signature before decoding, rejects noncanonical payloads, applies incremental diffs, and answers per-IP reputation lookups for the central abuse database.
- Scored-set pull client that fetches a full snapshot or an incremental diff from the central service and verifies it before use.
- Central scored-set consumer wired into the daemon under `reputation.central` (opt-in, default off): refreshes the verified set and, when a finding's IP is listed, challenges it (or hard-blocks only with local corroboration above the threshold). Firebreaks (loopback, private, documentation ranges, infra_ips) are never acted on; central data never blocks on its own.
- `csm report enroll` generates a node key pair for abuse reporting, and the dashboard settings expose the reporting and central-database options.

### Fixed

- CSM no longer raises sensitive-file alerts for changes it makes itself (e.g. installing a per-user WP-Cron job), while a later independent tamper of the same file is still reported.
- The Redis non-expiring-key warning no longer fires when the eviction policy can reclaim any key, still warns when the policy cannot be read, and now explains TTL-only and no-eviction cases accurately.
- WP-Cron remediation now uses configured account roots, keeps scheduling unchanged when a crontab install fails, ignores commented config examples, and serializes per-user crontab writes to avoid duplicate or lost cron lines.
- Concurrent central scored-set refreshes now keep the newest accepted cache version when overlapping pulls finish out of order.
- Central scored-set consumer now rejects a snapshot at version 0 or any version below the cached one, so a rolled-back or hostile endpoint cannot regress a node's set or pin it to perpetual cold pulls; the snapshot and its lookup set are swapped together so a concurrent refresh cannot be read torn; an unrecognized `central.action` is logged; and the RFC 2544 benchmarking range is firebroken alongside the documentation ranges.
- `csm report enroll` usage now appears in the CLI help and tells operators to store the generated private key in an environment variable.
- Abuse report delivery now refuses redirected collectors and serializes spool draining, avoiding credential leakage and duplicate sends.
- Abuse reporting now skips unusable targets during startup and clears its daemon hook when reporting is off, misconfigured, or shutting down.
- Scored-set updates now reject malformed or conflicting changes before they can alter a node's cached abuse score set.
- Scored-set update pulls now reject oversized responses and malformed cursor URLs before applying data.
- Central challenge-only decisions now expire without becoming hard blocks; hard blocking still requires the local corroboration policy.
- Central firebreaks now honor all configured infrastructure IPs before challenging or blocking a scored address.
- Central set pulls now reject non-loopback HTTP endpoints and older snapshots before replacing the cached scores.

## [3.12.0] - 2026-06-05

### Added

- A new mail-filter scan inspects per-mailbox and domain-wide Exim filters for account-takeover interception. Hidden-copy rules are reported as critical even when the filter predates CSM; plain external forwards remain change-gated, and repeated destinations across mailboxes are called out as a coordinated campaign.

### Changed

- Bumped `go-redis/v9` to 9.20.0 and the pinned `actions/checkout` and `github/codeql-action` workflow actions to their latest patch releases.

### Security

- The `.htaccess` scanner now flags PHP handler remaps to non-executable extensions, including Apache's dotless or quoted extension tokens and proxy-fcgi aliases. Legitimate cPanel MultiPHP mappings and PHP source-display handlers are unaffected.
- The `.htaccess` directive scanner, file-index handler overlay, and cleaners now join Apache line continuations before analysis and remove the full physical directive span, so split malicious directives can no longer slip past detection or leave orphaned lines.
- Surgical removal of prepended PHP injection now matches uppercase open tags, closing a gap where an injected block starting with an uppercase tag was left in place.

### Fixed

- A visitor who passes the challenge now skips the gate for the allow window through a signed, single-IP cookie. The previous verification cookie was never checked, so a verified visitor was re-challenged on every request.
- The authentication-event listener no longer leaks a goroutine at shutdown when the alert channel is no longer being drained.
- Automatic WordPress database cleanup now strips injected scripts loaded via protocol-relative URLs, which were detected but previously left in place. It also no longer reports a successful clean while the malicious script is still present.
- WordPress database cleanup now keeps legitimate external script embeds in place and refuses partial cleans that would leave an attacker script active.
- The WHM password-change hijack detector can no longer hang daemon shutdown when its alert channel is saturated; its alerts give way once shutdown begins.
- A panic inside a per-account security scan started from the web UI is now contained and reported as a check timeout instead of crashing the daemon.
- Refreshing the Cloudflare allowlist now fails cleanly when only one address-family set is initialized, instead of panicking.
- WHM access monitoring now keys off the served WHM port field, so byte counts and referer URLs cannot make unrelated requests look like WHM actions.
- Out-of-memory detection on older kernels now only reports recent events, instead of flagging a days-old event on every scan.

## [3.11.1] - 2026-06-03

### Security

- The daemon is now built with Go 1.26.4, which patches two standard-library vulnerabilities (a TLS certificate hostname parsing slowdown and unescaped input in mail/network error messages).

### Fixed

- Active incidents can no longer accumulate without bound when auto-close is disabled or a kind has no threshold. A hard safety cap now resolves incidents left open past a maximum age, bounds how many stay in memory at once, and drains large capped backlogs promptly.
- ModSecurity parsing now rejects pathological continuation-heavy rule files before they can consume excessive memory.
- The YARA scan worker now handles shutdown during startup without leaving the supervisor stuck waiting for readiness.
- The attack database no longer leaks memory tracking removed addresses on hosts that use the flat-file store, and it now reports a failed save instead of silently swallowing it.
- The GeoIP RDAP lookup cache is now hard-bounded even when every entry is recent, so a burst of distinct lookups can no longer grow it past its cap.
- `csm rehash` now exits non-zero when it fails to update the integrity hashes, so a scripted rehash-then-restart no longer proceeds on a stale hash and takes the daemon down.
- The YARA scan worker now contains a handler crash and returns an error for that one scan instead of dropping the connection, and a stopped scan worker no longer retries against its closed socket. Together these stop a single bad scan from wedging the scan path.
- ModSecurity rule parsing no longer drops an entire vendor rule file when it contains an unusually long assembled line. Such a file previously fell out of the rule-action registry, which could mislabel its pass and counter rules as real blocks.
- File signature scanning now reads the whole inspected region in one pass instead of a single read that could stop short, closing a gap where malware further into a file could be missed. An out-of-range read size is now rejected instead of crashing the scanner.
- Allowing an IP that falls inside a blocked subnet now warns that the address stays blocked until the subnet is unblocked, instead of reporting a success that has no effect.
- Backup restore now verifies the database snapshot before a full or firewall restore applies payloads, so a tampered or corrupted snapshot is rejected without a partial import.
- The verified-crawler DNS cache is now bounded. A scan from many unique source IPs could previously grow it without limit between periodic prunes, an external memory-pressure lever.
- Incident auto-close and retention background loops now stop during shutdown before the state store closes, so they no longer tick against a closed database or leak past daemon exit.
- Log watchers now close their files from their own polling loop on shutdown instead of from a separate goroutine, removing a teardown race on the file handle that could surface during a restart.
- The verdict callback now refuses an "allow" reply that carries no replay binding when an HMAC secret is set but response signing is not required. An on-path attacker could previously strip the nonce and timestamp to slip an unbound allow past the best-effort replay checks and disable a block.
- The `.htaccess` directive scanner no longer stops at an oversized line. An attacker could pad an early line past the reader's limit to silently hide a malicious directive after it; the scanner now reads past long lines and flags any file it still cannot fully parse.
- Permanent-block escalation now actually makes a repeat offender's block permanent. The promotion previously ran in the same cycle as the temporary block and was skipped as "already blocked," so the address kept its temporary timeout and silently expired instead of staying blocked.
- Permanent-block escalation now respects the permanent block cap when promoting a temporary block.
- The email spool watcher now exits cleanly on shutdown even if it crash-restarted moments earlier. A narrow race could previously leave a freshly restarted watcher running with nothing to stop it, hanging daemon shutdown until systemd killed the process and dropped in-flight scan state.
- Surgical file cleaning now refuses files above a size ceiling and quarantines them by rename instead. An attacker could previously match a signature in a file's first bytes, pad it to many gigabytes, and make the root daemon read the whole file into memory until it was killed.

## [3.11.0] - 2026-06-02

### Added

- A signed YARA Forge rule mirror lets operators turn on Forge rule updates with signature verification. Release artifacts and downloaded rules are now checked against the project signing key.
- Credential-stuffing detection: a single source IP that fails logins against many distinct accounts now raises its own alert, catching breadth-based attacks that the per-IP brute-force trigger (which keys on attempt count) misses.
- Outbound connections to a bad or unexpected network (by autonomous system) can now be flagged. Combined with a new root account or a planted privileged binary, this escalates an incident to a host takeover. Off by default; needs the ASN geolocation database and an operator ASN list.

### Fixed

- The auto-block rate-limit warning now fires once per hour instead of on every scan, so a sustained attack no longer floods the audit log with thousands of identical entries. The overflow queue is also bounded; once full, the warning reports how many addresses were dropped.
- The timed firewall-rollback now stores the previous ruleset as an nftables data file restored with `nft -f`, instead of a generated bash script. This removes a shell-injection surface where a crafted set name or comment in the live ruleset could break out into a root shell.
- Timed firewall rollback now keeps the pending rollback state when restore fails, and it can roll back hosts that had no prior nftables ruleset instead of silently treating them as confirmed.
- Firewall blocks now persist to state before the kernel rule is added, so a crash mid-block can no longer leave a permanent kernel block with no state record that a later rebuild would silently drop.
- Firewall block failures now report when their state rollback also fails, so operators can see when a failed block may still be restored on the next ruleset rebuild.
- The Server-Sent Events stream now caps concurrent subscribers and returns 503 when full, so a read-scope token cannot open unbounded long-lived streams to exhaust daemon memory.
- Imported whitelist IPs are now validated and normalized like every interactive route, so a crafted import bundle cannot poison the allow-list with malformed or non-routable entries.
- Process-context enrichment now caps how many deadline-bound `/proc` reads run at once. A process stuck in uninterruptible I/O can no longer leak an unbounded number of reader goroutines over time; once the cap is hit, enrichment degrades gracefully instead.
- Process-context reads configured with no per-file deadline now stay outside that deadline cap, matching the existing unlimited-read behavior.
- When the temporary-block cap is reached, the firewall now evicts the block closest to expiry to make room for a new one instead of refusing it. An attacker can no longer saturate the cap with disposable IPs to stop CSM from blocking the address doing real damage.
- Temporary-block eviction now happens only when a live block is applied. Dry-run decisions and panel allow verdicts no longer remove an existing temporary block.
- The verdict callback now refuses an unsigned "allow" decision unless the operator explicitly set `allow_unsigned: true`, so a missing HMAC secret can no longer silently disable auto-blocking.
- Configuration reloads (SIGHUP) now reach the realtime file monitor's path suppressions, log watchers, and mail-log reader. Threshold, infrastructure-IP, trusted-country, and suppression changes previously needed a full restart to take effect on those paths.
- BPF ring-buffer readers now close exactly once on shutdown and no longer leak their shutdown-watcher goroutine, removing a teardown race that could surface when a watcher restarts.
- Realtime auto-quarantine now relies on content-based obfuscation and execution signals instead of library path names.
- Package-integrity checks now report modified executable code by file type instead of a fixed directory list, while keeping non-executable package data quiet.
- Non-standard MySQL superuser accounts and operator WHM root API tokens are now surfaced on the first scan instead of being silently recorded as the baseline. If CSM is installed on an already-compromised host, accounts and tokens planted by an attacker are flagged for review rather than treated as known-good.
- MySQL superuser tracking now records clean scans, so later privileged-account additions are reported as changes. Older WHM output now feeds first-scan token review instead of silently trusting existing tokens.
- The PAM brute-force listener no longer emits alerts while holding its internal lock. A stalled alert consumer could previously wedge the whole login-monitoring path and let its failure-tracking memory grow without bound.
- Behind a trusted proxy, HTTP abuse detection now matches the challenge server's client-IP attribution instead of trusting client-supplied header entries.
- Subnet (CIDR) blocking now refuses ranges that cover infrastructure, local host addresses, allowed IPs, port-specific allows, or the default route. This prevents self-lockout and collateral blocks on shared ranges.
- Periodic malware and file-index scans now inspect every extension a PHP handler executes, not just `.php`, and honour `.htaccess` handler remappings, so a webshell hidden under a `.phtml`, `.php7`, or attacker-mapped extension is caught even when planted before the daemon started.
- PHP handler remap scanning now respects file-scoped handlers and catches mapped upload extensions without treating stock PHP-FPM handler blocks as every-file PHP.
- PHP content scanner now analyses only the code inside PHP tags, ignoring inline HTML, CSS, and JavaScript. This stops false positives on stock plugin and theme template files where markup text, page links, and script template literals looked like include, require, or shell-execution sinks.
- PHP content scanner no longer treats an include or require built from a server path such as the document root as remote-file inclusion, clearing false positives on standard WordPress bootstrap files.
- PHP include scanning keeps the server-path false-positive fix while still treating header-derived include targets as attacker controlled.
- PHP content scanner now reports the legacy preg_replace /e modifier only when attacker-controlled input reaches the call, consistent with its other sink checks. This clears recurring false positives on old plugins that run /e over internal data while still catching it as a real code-execution sink.
- PHP content scanner no longer misses legacy replacement-eval droppers when attacker input is staged before the call.
- WHM root API token alerts now name the token that changed and stay critical only when an operator token is added or removed or any token gains full access. Routine DNS cluster trust token churn is reported as a low-severity note instead of a recurring detail-free critical.
- WHM root API token monitoring no longer goes quiet when structured WHM output is unavailable, and manually added trust-suffix token names still page as operator token changes.

### Changed

- The PHP content scan now skips re-reading files that are unchanged since the previous scan, backed by a periodic full rescan and realtime file monitoring. On large multi-tenant hosts this keeps the deep scan from hitting its time limit and emitting spurious timeout warnings.
- PHP content cache full rescans now stay on the host-wide cadence even when account scans run between daemon cycles, files that become unreadable are retried, and empty readable files are cached as clean.

## [3.10.0] - 2026-05-30

### Added

- CSM now raises one per-vhost alert when many already-abusive HTTP sources focus on the same site in one scan window, making distributed botnet pressure visible without counting ordinary visitor spread.
- New supply-chain check parses `composer.lock` and `package-lock.json` dependency trees and flags versions listed in a local advisory database. The matcher ships in the binary; the advisory data is operator- or mirror-supplied (`docs/supply-chain-advisories.md`), and the check is dormant until that file exists.
- New check flags identical WordPress administrator password hashes across hosting accounts, a signal that one copied admin credential could unlock multiple sites. Raw hashes are not written to state, logs, or findings; only the affected account list and count are reported.
- The incident correlator now raises a `host_takeover` incident when a new uid-0 account and a planted suid binary are correlated for the same host inside the merge window, so a multi-step privilege escalation stands out from a single host-integrity finding.
- Auto-response can now drop confirmed-malicious database triggers, events, procedures, and functions when `clean_database` is enabled, recording a restorable backup first. Detection of these objects is unchanged; only the automated cleanup is new.
- Documented the fleet-correlation contract: how phpanel turns the signed per-finding webhook stream into one cross-host incident per attacker IP.
- Published an OpenAPI 3.1 spec for the `/api/v1/*` HTTP API covering every route with its method and auth scope. A drift-guard test fails the build if a route is added without documenting it.
- PHP content scanner now flags three more remote-code-execution shapes: preg_replace with the /e modifier, include or require of request input or a remote/stream wrapper, and assert or create_function driven by request input.

### Fixed

- Web UI API rate limiter now derives its per-client key with proper host and port splitting, so IPv6 clients are keyed individually and consistently with the login limiter instead of sharing a bucket.
- Web UI audit logs now preserve IPv6 source addresses that arrive without a port.
- PHP content scanner now ties the new remote-code-execution checks to the executable expression being scanned, reducing false positives from nearby literals or unrelated request reads.
- PHP content scanner now ties decoder obfuscation alerts to encoded callback construction instead of nearby string concatenation or unrelated encoded data, reducing false positives on large plugins.
- File-index scanner now judges every new PHP file in WordPress uploads by its content instead of skipping files by directory name or the index.php filename, so a webshell hidden in a "safe" upload folder or named index.php is no longer missed.
- Realtime upload monitoring now applies content checks before filename or update-directory handling, so malicious PHP in WordPress uploads is still surfaced while inert stubs stay quiet.
- PHP scanning no longer skips files by name or location in WordPress language, mu-plugins, and bundled-dependency directories, so a backdoor hidden under a translation-style filename or inside a vendor folder is now content-analysed like any other file. Structurally inert stubs stay quiet, and unreadable files fail closed instead of being treated as clean.
- Config integrity verification now covers the conf.d drop-in fragments, not just the main config file, so an attacker who edits a fragment to weaken settings is detected. Operators using conf.d should re-run `csm rehash` once after upgrading.
- Config integrity metadata now stays in sync when drop-in fragments change through reloads or settings saves, preventing false tamper failures after a legitimate edit.
- Config drop-ins that try to set integrity metadata are now rejected so signed hashes always come from the main config.
- Realtime malware quarantine now moves files through the same race-safe path as the scheduled dispatcher, rejecting symlinks and verifying the file did not change between detection and the move, so an attacker cannot redirect quarantine at an unrelated file.
- Quarantine cleanup now fails closed if a source path changes while the move is in progress.
- Realtime credential-log and .config executable detection now read file content and mode from the kernel event handle instead of re-opening by path, so an attacker cannot evade detection by swapping the file after it is written.
- Suppression patterns with a wildcard no longer collapse into an over-broad substring match, so a narrow ignore rule like `*.php` can no longer silently silence an entire directory subtree. Directory-style patterns such as `/uploads/` and `*/node_modules/*` keep working.
- The firewall IP lookup now checks cPanel brute-force records exactly instead of scanning raw output, so querying one address can no longer reveal or be confused by a different, longer address. The cPanel brute-force lookup is also time-bounded, and the incident status endpoint caps its request body.
- PHP malware analysis now understands heredoc and nowdoc string syntax, so a quote inside such a block can no longer hide a real eval/decode call placed after it, and template text inside the block is no longer mistaken for executable code.
- PHP malware analysis now preserves heredoc boundaries before normalizing source, so case-variant template text cannot hide executable payloads that follow.
- Suppression globs that target a specific directory now stay scoped to that glob instead of muting every deeper descendant that shares the same prefix.
- Web settings saves now reject stale drop-in integrity state instead of silently signing unrelated fragment edits.
- Automatic outgoing-mail hold on a spam outbreak, realtime cloud-relay credential abuse, or startup cloud-relay replay now respects the auto-response master switch and dry-run safety default, so an operator in monitor mode no longer has a customer's mail held without opting in. The finding still surfaces.
- Realtime malware quarantine now honors the live auto-response master switch and quarantine opt-in, matching the scheduled quarantine path, so an operator who disables file quarantine on reload no longer has files moved on a realtime signature match.
- The distributed HTTP flood threshold is now exposed in web settings, reference configs, and operator docs so it can be tuned consistently.
- Incident auto-close now starts shortly after restart instead of waiting a long warm-up, and drains a large backlog over several bounded sweeps rather than one. A frequently-restarted busy host no longer leaves thousands of long-idle incidents sitting open, and a big sweep no longer stalls incident ingestion or bursts the store.
- Default configuration templates now show the dedicated Prometheus scrape token so operators do not need to give scrapers the admin token.
- Documented how to tune per-kind incident auto-close thresholds on high-volume hosts to keep the open-incident set manageable.
- Phpanel per-finding webhooks now bypass operator alert suppression and rate limits, so panel-side fleet correlation receives the full deduplicated finding stream.
- Host takeover incidents now have a readable label and kind filter in the grouped incident view.
- The incident correlator now treats verified-crawler source IPs from published ranges (Googlebot, Bingbot, Applebot) as whitelisted, so legitimate crawler traffic no longer creates correlated incidents. CDN edge ranges are intentionally not whitelisted.
- HTTP request-flood and User-Agent-spoof findings now carry the originating vhost and report how many distinct vhosts a single IP hit, so an operator can see a one-IP-scans-many-sites pattern on shared hosting.
- Mail-log source recovery now marks the watcher healthy again when the file returns after a vanished-source alert.
- The mail-log reader now reports when its source file disappears mid-run (for example after a syslog-to-journald migration), marking the watcher unhealthy and emitting a finding instead of silently tailing a dead file with mail brute-force and rate detection going dark.
- Automatic database-object cleanup now fails closed on malformed metadata, so automated drops cannot target a different stored object than the detector reported.
- Prometheus firewall gauges now report live firewall rule counts after startup and in-process daemon rebuilds. They previously read a parallel store populated only at migration, so the blocked-IP and total-rule metrics could sit frozen while the real firewall state moved on.
- Pruning an old closed incident now also releases any leftover credential-spray tracking bound to it, so an orphaned binding cannot keep attacker state alive after the incident is gone.
- Blocked-IP lookups across the threat view, reputation skip-list, alert suppression, and the web UI blocked-IP list now read the live firewall engine state instead of a migration-time snapshot, so they no longer show or act on a stale set of blocks.
- The blocked-IP API now returns an empty list when the live firewall state has no active blocks, instead of a JSON null payload.
- A firewall block that is applied to the kernel but fails to persist now rolls the live rule back instead of leaving a block that would silently disappear on the next restart.
- The surgical PHP cleaner now strips include and eval injections even when the malicious line is padded with leading NUL or vertical-tab bytes, instead of falling back to whole-file quarantine.
- Surgical PHP cleaner reports now omit padding control bytes from stripped injection summaries.
- PHP content scanner now flags eval that wraps a variable function call or a dynamic code-construction primitive, closing an obfuscation path that decoder-only matching missed.
- PHP content scanner now flags backtick shell execution with request input, exec/decoder names passed as callbacks, and variable-variable function calls driven by request input.
- PHP content scanner now ignores those new execution patterns when they appear only in comments or quoted examples.
- PHP content scanner no longer flags a decode function used as a callback unless that same call is fed request input, clearing false positives on stock plugins that decode internal data while still catching attacker-driven droppers.
- PHP content scanner now treats request variables as exact input sources, avoiding literal or prefix-only matches in callback and dynamic-call checks.

## [3.9.2] - 2026-05-29

### Security

- Firewall block guard now refuses to auto-block any of the daemon's own non-loopback interface addresses, regardless of operator configuration. A stray internal request that loops back to the daemon could previously trigger a self-block and firewall every customer hosted on that IP.
- Database scan, clean, and auto-response paths now reject a WordPress table prefix that contains anything outside alphanumerics or underscore. A cPanel-user-owned wp-config.php can no longer drive SQL injection through these helpers.
- Surgical file cleaning now refuses symlinked targets or parent directories and writes replacements through a pinned directory handle. Cleaned files keep their original owner and mode while avoiding symlink write-through.
- Firewall infra-IP guard now matches the same numeric address whether the caller passes the canonical or IPv4-mapped-IPv6 form, so a misencoded incident IP cannot bypass configured or DNS-resolved infra protection.

### Fixed

- Regenerated AF_ALG BPF LSM object files so the kernel-side denylist program actually loads on Linux 6.12+. The C source was already fixed for the `bpf_d_path` trusted-pointer requirement, but the committed `.o` artifacts were stale and tripped the verifier with `R1 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_`, dropping AF_ALG enforcement to the auditd-tail fallback.
- Firewall infra-IP guard now runs before the IPv6-enabled check. A canonical IPv6 form of an infra address listed in `firewall.infra_ips` is now refused even when the engine has no IPv6 set bound, instead of returning an "IPv6 not enabled" error that the caller could misread as a transient config issue.
- Closing or auto-resolving a credential-spray incident now releases its attacker tracking state. Later failures from that address are evaluated as new activity instead of mutating the closed incident or reusing old spray counts.
- Incident recovery now ignores corrupt or internally inconsistent bbolt incident rows instead of letting one bad record block the list or compaction pass. Direct incident lookups still surface corrupt records as errors without marking them found.
- Alert shutdown now drains buffered findings after tracked workers stop, so last-second findings make it into the shutdown flush instead of vanishing on graceful restart.
- Aggregated WordPress login brute force, XML-RPC abuse, and user-enumeration findings now carry a validated structured source IP, so the incident correlator keys them under the attacker IP instead of silently dropping the per-IP attribution.
- Obfuscated-PHP content scanner now recognizes comment-disrupted eval/assert decoder chains more accurately while ignoring examples inside PHP strings.
- Daemon state files are now fsynced through the same atomic-write helper used by the firewall engine. A power loss between rename and directory sync can no longer leave the state file truncated and skipped by the in-memory hash gate.
- Credential-spray block audit now records "ok" only after the firewall callback confirms the block actually took effect. Dry-run and failed callbacks no longer log a false success on the incident timeline.
- Credential-spray blocking now coalesces concurrent findings while a firewall callback is in flight, preventing duplicate block attempts for one incident.
- Incident block audit now uses the firewall outcome, so dry-run, verdict-allow, and no-op attempts no longer look like live blocks.
- Panic inside an auto-block firewall callback now releases the per-incident in-flight slot, so a single bad integration cannot permanently latch the auto-block path for an open incident.
- Auto-blocking no longer risks a duplicate firewall callback when another matching finding arrives as a block finishes.
- Verdict callback now respects daemon shutdown. A wedged panel response can no longer keep auto-block workers waiting past stopCh during graceful restart.
- PHP-relay supervisor, exim history scan, and Flow E maintenance ticker now run under panic-capturing goroutines and are tracked by the daemon waitgroup. A large exim_mainlog scan also honors shutdown so it cannot outlive state close.
- PHP-relay startup replay now skips an oversized malformed log line and continues scanning later mail activity instead of abandoning the pass.
- Cloud-relay detector now evicts idle per-user windows on a periodic sweep, so the in-memory map no longer grows linearly with every authenticated sender ever seen.
- Cloud-relay cleanup no longer drops the first new mailbox activity when cleanup and log parsing happen at the same time after a long idle period.
- Firewall state reads now ignore expired allow-list rows the same way they ignore expired blocks, so stale entries no longer inflate firewall rule metrics.
- Incident persistence and restore failures now log a warning instead of being silently dropped. Operators see a signal when bbolt rejects incident state and the in-memory and on-disk views drift apart.
- Firewall audit log now logs when its file open fails. A disk-full or permission regression no longer drops audit entries silently.
- Dry-run block ledger now serializes its records through the JSON encoder. A control character in the block reason no longer leaves an unparseable row that hides the rest of the bucket from the dry-run review pane.
- Subnet auto-block now applies the operator-configured block expiry, matching the per-IP path. Escalated /24 blocks no longer outlive the configured TTL.
- Reverse-DNS lookup cache is now size-capped with oldest-first eviction. The BPF SMTP-egress detector can no longer accumulate one entry per ever-seen remote IP on a busy host.
- Fanotify plugin-stat cache now evicts entries that have not been re-stated in two times the TTL window, so a long-running watcher cannot accumulate one entry per distinct plugin slug ever observed.
- Surgical file cleaner now removes whole chr() chain statements that span multiple lines via the PHP concat operator. An attacker can no longer break the 5-chr-on-one-line gate by inserting a newline between calls.
- htaccess auto_prepend and auto_append detection now recognizes the `php_admin_value` variant in hardened and signature scans, closing the bypass that mod_php and some LSAPI builds expose.
- Alert dispatch now only consumes a per-hour rate-limit slot after at least one channel accepted the message. Failed sends no longer silently throttle the next non-critical alert, and concurrent dispatches honor the same hourly cap.
- Finding observer panics now log the escaped recovered value, observer id, and stack to stderr without letting panic-value formatting break later observers. A recurring observer bug surfaces in the daemon log instead of being silently swallowed.

## [3.9.1] - 2026-05-28

### Changed

- Bumped `github.com/VirusTotal/yara-x/go` to v1.17.0 and `github.com/oschwald/maxminddb-golang/v2` to v2.3.0; bumped the pinned `github/codeql-action` SHA to v4.36.0 in the CodeQL and Scorecard workflows.

### Fixed

- Web UI firewall rollback now avoids delayed daemon restarts after shutdown without canceling an in-progress manual revert restart.
- WAF high-volume attacker findings now drive the auto-block firewall path, even when challenge routing is enabled. The detector carries a structured attacker IP, and the auto-block kind list recognises it alongside other confirmed attack signals.
- Async bot verifier now cancels its in-flight DNS lookup when the daemon begins shutdown, instead of holding the worker for the per-job timeout.
- DynDNS resolver now passes a context-bounded deadline into every host lookup. A stuck DNS server can no longer hold a 5-minute tick beyond its budget and stack the next one on top of itself.
- Per-account scans now stamp the tenant ID on findings that the detector emitted without explicit attribution. The incident correlator can key those findings by account instead of falling back to weaker identities, so one account's compromise no longer fragments across multiple incidents.
- Per-account scans now reject findings whose structured file path belongs to another home account before tenant attribution, avoiding cross-account incident misattribution.
- Config validator now warns when auto-response wants to block IPs but the firewall section is disabled or missing. Previously the daemon logged auto-block actions that never reached nftables.
- Health check now warns when BPF direct-SMTP enforcement is enabled but the connection tracker is running on legacy or has no active backend. Operators see the threat-detection degradation in the health channel instead of inferring it from missing telemetry.
- conf.d fragment loader now logs scalar overrides with the fragment path and redacts sensitive values. Operators see which key was overwritten without leaking tokens into logs.
- Upstream threat-intel source now exposes cumulative cache hits, cache misses, backend failures, and breaker state through the existing Prometheus pipeline. Operators can monitor cache effectiveness and upstream health alongside the other csm_* metrics.

### Security

- Startup retro scan of `exim_mainlog` now caps per-user event history and total distinct users it holds in memory. A compromised account that bursts thousands of sends, or a crafted log run, can no longer grow that map without bound.
- Incident classifier now treats kernel module loads, /etc/shadow and sshd config writes, root password changes, new uid-0 accounts, new suid binaries, and root crontab edits as host-integrity incidents instead of generic web-account compromise. Severity escalation and operator filtering now match the actual blast radius.
- Verdict callback replay protection now fires on the response-signing opt-out path too. A panel that disabled response signing during rollout still has its echoed nonce and timestamp checked; a panel that echoes nothing keeps working unchanged.
- Account-scan truncated findings now name accounts whose files hit the cap. Operators can target the right tenant or threshold instead of seeing a host-wide total with no attribution.

## [3.9.0] - 2026-05-27

### Added

- Web UI gained per-operator preferences (table density, timestamp display, default auto-refresh) saved server-side under the operator's token, so settings follow operators across browsers. Accessible from a new gear button in the topbar.
- Web UI gained per-page named filter views. Filter / search / pagination state on findings, firewall, audit, threat, incident, quarantine, email, and ModSecurity pages can be captured under a chosen name and reapplied later from the topbar dropdown. Views are stored server-side, scoped to the operator.
- Bulk threat block / whitelist and bulk firewall unblock actions now surface a 30-second "Undo" banner. Clicking it dispatches the inverse operation through the daemon and records it in the audit log.
- Settings UI exposes the mail-log source / file / journal-units selector and the dovecot-postfix account-key extractor. Hosts on Debian-family or journald layouts can now switch sources without hand-editing `csm.yaml`.
- Default `csm.yaml` template ships sample `mail_logs`, `detection.direct_smtp_egress`, and `bpf_enforcement` blocks so operators can discover those features without reading source. Every sample stays inert (`enabled: false`, `dry_run: true`) to preserve existing safe defaults.
- API reference documents the new `/api/v1/prefs/*` and `/api/v1/undo/*` endpoints, including payload shape, scope, sanitisation caps, and the 30-second undo TTL.
- Dashboard Components matrix now distinguishes "deaf" watchers (attached but no upstream feeding them, e.g. PAM listener with no PAM hook installed) from healthy quiet "idle" rows. The PAM listener surfaces a deaf verdict with a tooltip pointing to the missing `pam_csm.so` install.
- Package now ships a CSM PAM module plus a `csm pam install/uninstall/status` subcommand that stages it under the platform security dir and adds the optional auth/session lines to the standard PAM service files, taking a timestamped backup of every edit. Operator guide in `docs/operator-pam-install.md`.

### Changed

- CSRF protection now covers PUT and PATCH in addition to POST and DELETE for cookie-authenticated browser sessions. Bearer-token API callers continue to bypass CSRF, unchanged.
- `/api/v1/capabilities` now advertises `webui.prefs.v1` and `webui.undo.v1` so phpanel can feature-detect the new operator preferences, saved views, and bulk-undo endpoints without sniffing the daemon version.
- Packaged and standalone installs now use the same sandboxed systemd unit while preserving required host access for CSM monitors and remediation paths.

### Security

- Email attachment and archive-entry filenames are now stripped to the base name and stripped of control characters before they reach audit logs, alerts, or the web UI. Crafted zip/tar entries can no longer smuggle path-traversal segments or forged log lines through the scanner.
- Quarantine restore now applies restored modes before ownership changes and rejects restore attempts when the destination changes mid-restore.
- Firewall interval-set builders now reject or skip ranges whose end marker would wrap from the all-ones address to all-zeros. Misconfigured top-level CIDRs no longer widen allow or block sets to match every IP.
- WordPress core and plugin file checksums now compare with a constant-time hash comparison, removing a theoretical side-channel during integrity verification.
- Verdict callback requests now carry a per-request nonce and timestamp that the panel must echo in its signed reply, and replies whose clock drifts more than five minutes are rejected. Captured "allow" replies can no longer be replayed against a fresh block decision, and nonce-generation failures fall back to the default block path.
- Firewall expiry cleanup now reads stale entries before pruning so temporary allows and subnet blocks can actually be removed from nftables. Failed nft queue operations keep local state intact, and startup restore aborts instead of applying a ruleset missing persisted entries.
- Auto-block tracker, perm-block tracker, and firewall state now use private atomic writes. A daemon crash or power loss mid-write can no longer leave a torn JSON file or reuse stale temp-file permissions.
- Auto-netblock escalation now handles IPv6 attackers by collapsing per-IP blocks to a /64 CIDR. Previously the prefix extractor only understood IPv4, so IPv6 botnets rotating inside their assignment never triggered the subnet-block path.
- PHP content detection now catches Unicode-escape function-name obfuscation while limiting the match to the callable target. Unicode-escaped labels or other callback data no longer raise this alert on their own.
- Mail-log and access-log tailers now bound tail windows and skip oversized records before continuing. Attackers can no longer use a huge log record to consume unbounded memory, stall tailing, or feed truncated content to detectors.
- Upstream threat-intel client now caps its per-IP score cache and trips a circuit breaker after consecutive upstream failures. Sustained attack traffic from unique IPs no longer grows the map without bound, and a dead upstream only receives one probe when the cooldown expires.
- Internal metrics vectors now cap distinct label-value combinations and collapse overflow into a single sentinel bucket. Per-IP or other user-controlled labels can no longer grow the metrics map without bound.
- Mail-spool body parser no longer pre-stats the file before opening it. The size check now reads from the same open descriptor, so an attacker cannot swap the file for a larger one between stat and read to bypass the memory cap.
- Email AV tempfail mode now defers messages when MIME extraction is partial, including bodies that exceed the parser memory budget before any attachment is scanned.
- Email-attachment extraction now stages temp files under a daemon-owned 0700 directory instead of `/tmp`. An unprivileged local uid can no longer race the scanner via temp-file symlink swaps in a shared directory.
- Email AV now treats attachment staging failures as incomplete extraction instead of falling back to shared temp or delivering the message as scanned.
- Email-quarantine cross-device fallback now opens the source by file descriptor, copies from that descriptor, and verifies the source path still names the same inode before unlinking. A swap of the source mid-copy is rejected.
- Email quarantine now fails and rolls back when moving one half of a message fails unexpectedly, instead of reporting a partial quarantine as success.
- Web UI CORS check now derives the allowed origin from configuration instead of the request's Host header. A proxy attacker can no longer pair a forged Host with a matching Origin to bypass the cross-origin check, while equivalent configured origins still work.
- Process-context enrichment now checks process start time before using cached or refreshed process details. A PID-reuse race no longer attributes a new process's identity to the original event.
- YARA IPC now caps frames per connection so a malicious or wedged peer cannot pin one worker goroutine with an endless small-frame stream. The daemon reconnects after a cap close instead of dropping the next scan.
- Standalone PAM source now mirrors the packaged non-blocking socket path, and PAM writes suppress SIGPIPE. Stalled or closed daemon sockets can no longer hang or kill a login process.
- Config loader now rejects YAML input over a 4 MB cap on the main file and on each `conf.d` fragment. A malformed or attacker-supplied file can no longer force the YAML parser to allocate unbounded memory.
- Control socket now verifies peer credentials via SO_PEERCRED before reading any payload. The 0600 permission remains the primary defence; this defence-in-depth check refuses any non-root caller even if the socket ever becomes reachable from a less-privileged context.
- Signature update and YARA Forge download URLs now require HTTP or HTTPS and are rejected if they point at loopback, link-local, or RFC1918 / ULA hosts. A staging URL accidentally left in a production config now fails validation at startup.
- Web UI CSP no longer allows `unsafe-inline` for styles. Templates and bundled stylesheets contain no inline `style="..."` attributes, so an XSS payload that drops a `<style>` tag is now refused by the browser.
- BPF ringbuf reader now warns when dropped events show consumer back-pressure, so operators see the problem in the daemon log instead of having to query the counter manually.
- Mail-log reader now re-stats the watched path after every EOF and at a one-minute safety-net interval, then reads replacement logs from the beginning. A logrotate at the end of a busy spool minute is picked up by the next poll tick without skipping lines already written to the new file.
- Compound webshell-plus-C2 incident classification no longer relies on the trimmed timeline. Sticky flags persist on the incident itself so a long, noisy attack still escalates when the matching counterpart arrives much later.
- Periodic and initial scans now snapshot the live config once per tick, so a SIGHUP landing mid-tick can no longer split detection and auto-response between old and new policy.
- Periodic integrity checks no longer raise a tamper alert when a valid config reload finishes while the check is hashing the old snapshot.
- PAM service files are edited atomically without changing existing permissions or final symlinks, so a concurrent sshd or login no longer reads a truncated file mid-write during install or uninstall.
- YARA rule directory and every rule file are now perm-checked before compilation. CSM refuses to load rules a third party could overwrite, so an attacker cannot disable detection by dropping a no-op rule.
- Email attachment scanning now treats a YARA-X backend loss or scan error as an incomplete scan. In tempfail mode, CSM defers the message instead of delivering it as scanned clean.
- Hostnames in top-level or firewall `infra_ips` are DNS-refreshed into the firewall guard, so management hosts declared by name stay protected as addresses rotate.
- Upstream threat-intel URLs now require HTTPS unless they point at loopback, preventing bearer tokens from crossing the network in plain HTTP.
- Inline code-injection cleaner now sees through comment-based evasions, and the PHP content detector flags indirect eval and shell-exec sinks without false positives on benign decoder callbacks.
- File quarantine now hardlinks or copies from a verified descriptor before unlinking the source, defeating the swap-the-file race and symlink-substitution attempts.
- Operator-supplied config-fragment directories are validated before any fragments load; refused paths fail startup so an attacker cannot redirect CSM at untrusted fragments.
- CSM requires signed verdict-callback responses by default when a secret is configured, preventing forged block-decision downgrades; operators can opt out during staged panel rollouts.
- Backup restore refuses to follow pre-existing symlinks under configured restore destinations, defeating attacker-planted redirections to system files.
- Verdict-callback startup now refuses to enable an unsigned channel by default; the daemon errors when the configured HMAC secret env var is missing unless operators explicitly opt in with `allow_unsigned: true`.

### Fixed

- Verdict-callback settings validation now blocks unsigned enabled configs unless `allow_unsigned: true` is set, matching daemon startup checks.
- Webhook dispatcher now drains small HTTP responses and shares one transport, so repeated alerts can reuse keepalive connections instead of opening a new TCP/TLS session each time.
- Access-log brute-force handler parses each line with a zero-allocation scanner instead of splitting into a string slice, halving CPU time and removing per-line garbage during sustained POST floods.
- Access-log scanner now preserves the previous field handling for unusual whitespace and malformed quoted methods.
- WordPress checksum-fetch retry timers now observe the file-monitor stop channel, so daemon shutdown cancels pending wp.org retries instead of letting an hour-long backoff fire against torn-down state.
- Auto-block bookkeeping no longer rescans the full blocked-IP list to deduplicate each new entry, cutting persistence cost from linear to constant on hosts that already track thousands of blocks.
- Firewall state saves now keep the in-memory cache keyed to the renamed file, so repeated auto-block updates do not fall back to reparsing state from disk.
- Account scans no longer block on a process-wide mutex held for the entire scan; scope travels via context so operators can run parallel account scans without one starving the other.
- Account scans now keep filesystem, WordPress, database, plugin, and PHP-isolation checks inside the requested account instead of surfacing cross-account or global temporary-directory findings.
- Access-log tracker eviction now trims least-recently-seen live entries after a unique-IP burst crosses the soft cap, so the map does not wait for stale entries before shrinking.
- Malware-cleaning matchers are now reused during infected-file remediation without broadening surgical-clean matches, cutting CPU and GC pressure on hosts under sustained webshell load.
- Account-scanner cap warnings now follow scan alert mode, so manual dry-run checks show the coverage warning without sending daemon alerts.
- BPF-backed live monitors now emit a `bpf_unavailable` finding when the kernel cannot run the requested program, and the finding says whether CSM fell back or lost live coverage.
- Incident persistence is now serialised across concurrent merges, so the disk record can no longer be overwritten by an older snapshot when two threads race.
- Incident auto-block now skips incidents closed before the block decision, preventing stale firewall hand-offs after an operator resolve or dismiss.
- Ordered incident writes now cover bulk and stale closes without blocking re-entrant incident reads.
- Incident kind reclassification now promotes active post-exploit chains on merge without weakening higher-risk incidents.
- Process identity no longer splits mailbox, domain, or account incidents, so multiple workers attacking one victim now count toward the same incident threshold.
- Mailbox findings are canonicalised before correlation, so the same actor lands in one incident whether the emitter set the full local@domain form or split it into Mailbox + Domain.
- Mailbox incident grouping now keeps the site context visible while merging mixed emitter formats across restarts and spray detection.
- Long-running incidents now cap their persisted finding fingerprints and operator-visible timeline, so a low-severity sustained event no longer grows memory and persistence payloads without bound.
- Incident truncation markers now report the full elided count, and generic auto-block no longer trusts a truncated timeline when the source IP is not part of the incident key.
- Firewall Apply now seeds persisted blocked and allowed entries into the same atomic netlink transaction as the table swap, removing a brief window where the new ruleset existed with empty deny sets.
- Firewall deny-limit cap now counts from the live kernel set, so an entry the kernel already expired no longer trips the cap and refuses a fresh block.
- Firewall deny-limit caps now preserve whether a live block was requested as permanent or temporary, so inherited nft timeout metadata cannot charge it to the wrong cap.
- Dry-run-block records are now purged whenever auto-response is live at startup or after reload, and stale dry-run records are aged out after a week so status does not report old dry-run windows.
- Auto-block hourly rate cap is now configurable via `auto_response.max_blocks_per_hour`, exposed in Settings, and documented in shipped config templates.
- Firewall startup wires dry-run and verdict callbacks before applying nftables and keeps the dry-run safety default from depending on startup ordering.
- Auto-block now installs the firewall engine via an atomic pointer and keeps IP and subnet decisions on one scan snapshot, so a SIGHUP rewire cannot split a scan across two engines.
- Auto-block tracker reconciles against the live kernel firewall before pruning cached state, so stale entries no longer suppress re-blocking after an IP expires.
- C2, backdoor, and suspicious PHP execution findings now carry stable actor keys, so repeat events group into one incident instead of splitting by process restart or missing UID.
- Initial baseline dispatch no longer double-notifies scan-produced cross-account correlation alerts.
- Auto-block no longer credits dry-run intercepts or verdict-callback allow responses as real blocks; dry-run intercepts surface as a Warning-level notice instead.
- Auto-block ignores unknown firewall result codes instead of treating them as successful blocks.
- Firewall blocklist size reported via the status API now reflects the live kernel count, so the panel agrees with the CLI.
- `/api/v1/status` now reports a real `baseline_at` for the daemon's first-start timestamp instead of the epoch. It stays stable across restarts, upgrades, and baseline resets.
- Manual check and baseline scans now keep dry-run state local to that scan, so they cannot mute live auto-response from daemon ticks.
- Settings saves now reject invalid mail-log source and account-key extractor values before writing the config.
- Web UI saved-view deletion, timestamp preferences, undo re-blocks, and CSRF checks now behave correctly with mixed credentials and missing firewall engines.
- Redis performance check test now stubs the in-process redisinfo client through its documented test hooks instead of relying on a default-config redis being present on the developer's machine. The dead redis-cli shellout fixture is gone.
- Web UI modal, tab, and detail-panel actions now initialize correctly with the bundled Tabler scripts.
- PAM packaging now builds the module before nFPM runs, and uninstall only removes CSM-managed hook lines.
- Oversized files inside tar.gz email attachments now mark extraction as partial, matching zip handling.

## [3.8.1] - 2026-05-25

### Fixed

- Package upgrades no longer fail or drop the CSM binary's immutable hardening on hosts where the previous version had locked the binary down. Closes #14.

## [3.8.0] - 2026-05-25

### Added

- ModSecurity rule management table gained search, status / action / escalation filters, sortable columns, pagination, persistent state, and an empty-state placeholder so operators with many custom rules can find a specific entry without scrolling the full list.
- Rule files list gained a search box and a YAML / YARA type filter.
- Findings history pager now shows numbered pages instead of only previous and next, so deep ranges are reachable in one click.
- ModSecurity blocked-IP and recent-events tables, and the email findings table, now render a friendly empty state when no rows match the active search or filter.
- Firewall subnet / allowed / whitelist tables, the audit log table, and the threat intelligence attackers table now persist their pagination, sort, and search state across reloads and stack rows as cards on narrow viewports, matching the other CSM.Table-driven pages.
- Cleanup history bulk restore and bulk delete now disable their trigger button for the duration of the request, preventing double-submits that would clone work or double-delete rows.
- Added a hot-reloadable account scanner cap so large hosts can bound account-scoped and mail-domain file iteration without relying on check timeouts. The new threshold is available in the sample config and settings UI.
- Web UI audit log and threat intelligence search boxes now persist to the URL, so filtered views are bookmarkable and shareable.
- Account detail tabs now support column sort, pagination, and persistent state, and the correlated incidents list uses shared table sorting while keeping its server-side pager.
- Web UI header shows a shared "Updated Xs ago" pill with manual refresh and auto-refresh pause/resume controls, so operators can freeze background refresh while still fetching on demand.
- Web UI hardening audit, performance monitor, account detail tabs, and ModSecurity rules listing now expose CSV / JSON export through the same dropdown style used elsewhere, and the audit log uses the same helper. CSV cells are guarded for spreadsheet safety.
- Web UI bulk-action bars share a new helper that tracks selection state, drives the select-all indeterminate, syncs per-button labels ("Restore 3 file(s)"), and disables / hides the buttons when nothing is selected. Quarantine page migrated as the first consumer.
- Audit log page gained search, action-type, and from/to date filters that persist to the URL. Action choices follow the actions present in the log, and date ranges include the full selected days.
- Account detail tabs now each render their own toolbar: findings can be filtered by severity and check type, quarantine by path, history by severity and date range, and exports follow the active filters.
- Quarantine page gained account, detector, and from/to date filters in addition to its existing path search. Account and detector dropdowns are populated from the current quarantine contents and all five filters persist in the URL.
- Email quarantine tab gained a toolbar with sender / recipient / subject search, direction filter, date range, and bulk release / delete buttons backed by the shared selection helper.
- Threat intelligence top-attackers table now supports country, verdict, and last-seen date-range filters. Country choices are derived from the visible attacker list and all filters persist in the URL.
- ModSecurity blocked-IPs tab gained per-row checkboxes and a bulk-disable button that writes CSM custom rule overrides and reloads ModSecurity in one click, so operators can clear noisy CSM rules straight from the blocks view.
- Settings page now deep-links via `?section=` instead of `#hash`, so bookmarks and external links land on the right section and the browser back button navigates between sections without losing unsaved fields. Old `#section` links still resolve on first load.
- Page templates now use unique element IDs across the whole UI: firewall, audit, threat, and ModSecurity rules pages were each assigning the same id to different inputs / tables / forms, which is a latent foot-gun if any of those pages ever load alongside another.
- Web UI accessibility: account tabs now wire `aria-controls`, the threat attackers "select all" checkbox carries an `aria-label`, the performance findings list is marked `aria-busy` while loading, error toasts announce with `aria-live="assertive"`, and the shared detail panel traps `Tab` focus while open so keyboard users do not lose context to the page behind it.
- Rules page "Import State" upload now shows an "Importing..." status with `aria-busy` while the import POST is in flight, then restores after success, failure, or parse error so a slow import no longer looks like a frozen page.
- Keyboard shortcut help overlay (`?`) now groups shortcuts by context (General / Navigate / Findings page), opens as a labelled modal dialog, and keeps keyboard focus inside it while visible.
- Web UI header gained a "What's new" button with a notification dot whenever the running daemon version differs from the version the operator last acknowledged. Clicking it opens the GitHub releases page and clears the dot.
- Web UI header shows a "Live updates" status pill backed by the existing `/api/v1/events` SSE stream, with connecting / connected / reconnecting / offline states, capped exponential reconnect, and a tab-hidden close so dropped streams are visible at a glance.
- Live updates now ignore callbacks from stale SSE streams during reconnects, so a late event from a closed stream cannot repaint the header with the wrong state.
- Web UI gained a Ctrl-K / Cmd-K command palette that fuzzy-matches every sidebar page, navigates with arrow keys, and traps focus while open. The shortcut is listed in the help overlay.
- Web UI ships a print stylesheet so the incident, audit, and findings pages render as static evidence: nav / topbar / toasts / toolbars are hidden, tables expand to show every row, and a "Printed from URL on TIMESTAMP" footer is stamped at the bottom of the printed output.
- Web UI contrast: severity badges, outline-button states, and muted helper text now meet WCAG AA contrast in light and dark themes.
- Web UI narrow-viewport polish: firewall config tables are wrapped in `table-responsive` so they don't overflow on phones, and the topbar's "Live updates" / "Updated Ns ago" labels visually collapse below 576px while keeping status updates available to assistive tech.
- Web UI CSP audit now pins executable scripts to same-origin static assets and rejects inline executable script tags in templates. The keyboard shortcut row highlight now lives in the static stylesheet instead of a runtime style block.
- New `thresholds.crontab_base64_blob_max_bytes` operator override for the crontab deep-scan base64 decoder cap (default 16384). Lets operators raise the cap on hosts where `csm_checks_crontab_base64_truncated_total` shows recurring truncation without rebuilding the daemon.

### Changed

- The performance dashboard now reads Redis memory and keyspace stats via the in-process `redis/go-redis` client instead of shelling out to `redis-cli` twice per poll. Eliminates two forks per sampler cycle on hosts that surface the dashboard. Fail-fast timeouts (500 ms) preserve the previous behaviour when redis is absent.
- The CMS database content scanners (WordPress / Joomla / Drupal / Magento / OpenCart) now run their per-account MySQL queries through the in-process `database/sql` + `go-sql-driver/mysql` pair instead of forking the `mysql` CLI with `MYSQL_PWD` env. Same per-account credentials, same row output shape, no subprocess per query.
- The root-credential MySQL checks (MySQL superuser audit, MySQL global variable / status / processlist performance audits, the WordPress transient-bloat scan, the database-object cleaner, the forensic SQL dump path, and the performance-dashboard connection counter) now run through the same in-process `database/sql` pair. Root credentials are read once from `/root/.my.cnf` and the connection is pooled across calls.
- The Redis performance audit (maxmemory / maxmemory-policy / keyspace / save / used-memory headroom) now uses the in-process `redis/go-redis` client instead of forking `redis-cli` four times per cycle.

### Fixed

- Web UI toolbar filters now keep a compact inline layout on pages with multiple dropdown and date filters instead of stretching or overflowing the row.
- Web UI topbar "Refresh now" now updates one-shot pages instead of silently doing nothing, falling back to a full reload when the page has no in-place refresh handler. Repeated in-place refreshes no longer leave stale table filter handlers behind.
- Dashboard Components matrix collapses idle watchers (attached but no events in the 7-day lookback) into a single "N watchers idle" disclosure with one marker across browsers, so degraded and active rows stay prominent. Idle is the normal state on hosts that simply have not generated those events yet.
- Web UI print output now includes all rows from the current filtered table view, hides the findings bulk bar, and keeps an open evidence detail panel in the printed page.
- Web UI command palette no longer lets Ctrl-K / Cmd-K also trigger page shortcuts behind the overlay, and it ignores keys already handled by another open modal.
- Threat intelligence attacker filters now match clean verdicts and keep bookmarked filter state even when no attackers are listed.
- Email quarantine toolbar filters now stay separate from findings filters, bulk select-all survives empty-to-populated reloads, and relative timestamp refresh no longer collapses message rows.
- Quarantine page filters now keep search scoped to file paths, clear stale dropdowns after the list empties, and use calendar-day date bounds so local DST changes do not hide rows.
- Quarantine bulk actions now reset after a list refresh, so select-all and the action buttons do not point at stale rows.
- URL-bound web UI search inputs now clear stale saved table filters when a shared link has no search query, and they reapply state after browser history navigation.
- Shared Web UI table sorting now reorders rows before paginating, so sorted pages display in the requested order.
- Shared web UI path safety checks now continue resolving traversal through missing path segments, keeping later symlink escapes blocked.
- Threat intelligence IP lookup now escapes account names before listing them, and country flag rendering ignores malformed country codes instead of breaking the page.
- Every web UI page now routes its API calls through the shared request helper, so a hung backend can no longer freeze a tab indefinitely. GET, POST, DELETE, and live-data poll requests share the same 30-second timeout.
- Web UI live-data poller no longer wedges when a page's handler throws or the request helper itself fails, preserves error backoff across tab hide/show cycles, and ignores stale timer callbacks after the tab is hidden.
- Web UI event stream now exits when shutdown starts and bounds each write, so active or stuck clients cannot hold daemon shutdown open.
- Web UI history, incident timeline, and ModSecurity blocks endpoints now cap how much they keep in memory per request and report `X-CSM-Truncated` when the cap is reached, so a single request cannot exhaust the daemon on a busy host.
- Web UI truncation warnings now reflect real capped results for history and ModSecurity block views, avoiding false warnings at the exact cap and missing warnings when an upstream scan cap is hit.
- Web UI CSRF coverage is now pinned by runtime checks that exercise every mutating API route without a CSRF token and assert the request is rejected, so a future route addition without the guard cannot ship unnoticed.
- Email quarantine actions now reject malformed message ids and unexpected path suffixes, shared path safety checks reject symlink escapes, and cPHulk flushes re-validate IP input before exec.
- Web UI error toasts shown by the global request helpers, the email release / delete actions, and the hardening audit error path now render with the danger styling. They were previously passing an unrecognized type string and falling back to the info color, hiding their severity.
- Rules page suppression list now formats the created-at timestamp through the shared `CSM.fmtDate` helper so the format matches every other timestamp in the UI.
- Shared Web UI number and percent formatters now leave missing values blank instead of displaying them as zero.
- ModSecurity rule table filters now track staged enable and escalation changes, and table filter selections persist across reloads.
- ModSecurity blocked-IPs bulk disable now preserves existing disabled rules and reports reload rollback failures instead of showing success.
- Web UI refresh buttons now use a single ghost-secondary style across pages instead of the mix of info, outline, and ghost variants that drifted in earlier releases.
- Audit log page export is now a CSV / JSON dropdown matching the export control on findings, firewall, threat, and email.
- Firewall configuration tables now render with the same card-table styling as the other firewall tables instead of plain defaults.
- Firewall Flush blocked IPs button uses the solid danger style so destructive-action colors are consistent across the UI.
- Web UI sidebar uses the full page title "Threat Intelligence" instead of the abbreviation.
- History tab deep links no longer assume Bootstrap is loaded and still open the History view when the tab helper is unavailable.
- Firewall audit filter row no longer relies on an invisible spacer label for alignment.
- Redis performance headroom alerts now calculate percentages from the raw Redis counters before display clamping, avoiding false high-usage alerts on very large memory values.
- In-process MySQL database scans now honor configured host, port, and socket targets, and root credential loading no longer stalls.
- Redis performance telemetry keeps using the inherited `REDISCLI_AUTH` password when local Redis requires authentication.
- Realtime crontab alerts now honor the configured base64 decode cap, and the settings UI exposes the same control as the sample configs.
- Account scanner caps no longer hide root or system cron baselines, global hidden temp files, or duplicate filesystem backdoor paths when globs overlap.
- Blocked-IP alert suppression now logs corrupt state once per filter pass and still uses valid queued-block entries when another state section is malformed.

## [3.7.0] - 2026-05-23

### Performance

- Firewall engine now caches the parsed `state.json` in memory and answers blocked-IP and blocked-subnet lookups from an index map instead of re-reading and re-parsing the 325 KiB state file on every call. Eliminates the per-call full file load that dominated steady-state CPU on busy hosts.
- IP-reputation check fans out the per-cycle AbuseIPDB queries in parallel instead of running them in a serial loop, so the check's wall-clock latency drops from ~5x single-call latency to roughly one call's worth.

### Security

- Closed the CodeQL findings backlog with stricter archive import containment, safe challenge and quarantine logging output, bounded parser/allocation paths, and safe numeric handling for proc-derived values.
- Email quarantine release now fails closed when the original spool directory cannot be resolved on disk, instead of falling back to comparing unresolved literals against the allowed list.
- Bumped `golang.org/x/net` 0.54.0 -> 0.55.0 to close `GO-2026-5026` (idna ASCII Punycode label handling) which `govulncheck` flagged via `internal/emailspool/parser.go`.

### Changed

- Per-account scanners (SSH key audit, cPanel API token audit, Dovecot mailbox password audit, the Magento, Joomla, Drupal, and OpenCart database content scanners, the MySQL persistence-object scanner, the mail forwarder / vfilter audit, the filesystem backdoor + hidden-file scanner, and the crontab + cron.d auditor) now rank recently modified accounts first and stop sooner on scan cancellation, so late-alphabet accounts are no longer systematically hidden when a check timeout cuts iteration short.
- WP brute-force domlog discovery is now consolidated in one helper shared by both scanners. Resolved central access-log targets are excluded from the per-vhost pass to avoid duplicate counting when paths overlap.
- Large access logs now honor the requested tail depth instead of stopping at a fixed byte window, so raised domlog limits work on high-volume domains.
- The real-time PHP webshell detector now relies on the upstream read window instead of silently discarding extra content before matching.

### Added

- New `thresholds.domlog_tail_lines` knob (default 500) controls how many trailing lines the WP brute-force scanner reads from each per-domain access log. Raise on hosts where slow-burn attacks against high-volume domains spread across more than 500 lines per scan interval.
- New `thresholds.domlog_max_age_min` knob (default 30) controls how many minutes back the WP brute-force scanner accepts a per-domain access log as fresh. Raise on low-traffic hosts where a slow-burn dictionary attack against a quiet domain still needs to fall inside the window.
- Mail-rate and FTP login scanners now let operators tune how much recent log history is read per cycle, so busy hosts can keep burst activity visible without a rebuild.
- Added real-time PHP content-scan truncation telemetry so operators can see when large files exceed the scan window before tuning limits. The same counter now also covers per-user crontab, per-vhost .htaccess, per-vhost .user.ini, HTML phishing, and CGI-script real-time checks.
- Added domlog discovery drop telemetry so operators can see when broken symlinks or stat failures silently shrink the per-vhost scan set.
- Added crontab base64 truncation telemetry and raised the per-blob decode window so operators can spot large encoded cron content that needs follow-up.

### Fixed

- AbuseIPDB fan-out now stops at the remaining daily quota slots before sending requests, so a cycle near the cap cannot spend past the circuit breaker.
- Firewall state cache now detects external state replacements even when timestamps are preserved and keeps the last valid snapshot during malformed rewrites, avoiding stale or empty block answers.
- Crontab and cron.d change baselines now ignore unreadable files instead of treating read failures as empty content, avoiding false change alerts during delete or permission races.
- Filesystem backdoor and hidden-file ranking now filters unreportable glob matches before mtime work, so unrelated or safe entries cannot consume the cancellation budget before suspicious candidates are checked.
- Canceled mail forwarder audits no longer mark the scan as fresh before finishing, so the next cycle can retry skipped domains.

## [3.6.0] - 2026-05-22

### Added

- Optional HTTP request-flood and User-Agent spoof detection on web traffic. Request-flood detection ships disabled until an operator sets a threshold, and User-Agent spoofing verifies search-engine bots by reverse DNS before flagging.
- `csm store reset-bot-verify` drops every cached PTR+forward-A result so the next scan re-runs reverse DNS verification for each crawler. Use after a verifier-logic upgrade that would invalidate prior negative cache entries (for example, adding a new bot domain suffix). Requires the daemon to be stopped, same as `csm store compact` and `csm store import`.
- Bot-verifier cache is now tagged with an internal logic version. The daemon compares the stored version with the running build on startup and clears the cache automatically when it differs, so a deploy that adds a new bot domain or UA mapping no longer requires the operator to remember to run `reset-bot-verify`.

### Changed

- WP brute force domlog scan now ranks per-domain access logs by recent activity before applying the file cap, so late-alphabet domains on hosts with thousands of vhosts are no longer hidden from the login, xmlrpc, and user-enumeration counters. The cap is operator-tunable and the scan stops promptly on shutdown.
- `sensitive_file_modified` now demotes High to Warning when a package-manager log was touched in the last 2 minutes or, on BPF hosts, when the writer's process tree contains a package manager. A cron drop-in containing obvious persistence tokens (curl|sh, base64 decode, /tmp/, eval) keeps High regardless, so CloudLinux upgrades stop paging without giving attackers a quiet path.
- `new_php_in_uploads` now demotes High to Warning when the dropped file's content shows no obfuscation, remote-payload, or shell-execution indicators. Files that fail to read, are empty, or trip any heuristic stay High, and the deep-tier PHP content scanner still emits its own finding independently, so a real webshell still surfaces at the original severity.

### Fixed

- User-Agent spoof detector no longer fires on IPs that have no reverse DNS at all; only PTR records that resolve outside the claimed bot's published domain still count as spoof. Amazonbot is now recognised on Amazon's `.amazon` top-level domain, and Meta's `meta-externalagent`, `meta-webindexer`, and `facebookexternalhit` crawlers are recognised on Meta's `fbsv.net` and `tfbnw.net` proxy networks, so the legitimate crawlers stop paging operators as critical.
- `new_php_in_uploads` and `php_in_uploads_realtime` now suppress only PHP upload stubs whose full reachable code is comments/whitespace or a no-argument terminator. BackWPup-style working files stop paging, while truncated files, line-comment close-tag escapes, and `die`/`exit` calls with arguments stay visible.
- `shadow_change` suppression now also consults successful WHM api tokens log entries, so admin-initiated suspend, unsuspend, password reset, and account create/remove calls from infra IPs no longer page operators. The session-log only path missed every suspendacct, treating each billing-system suspension as a critical incident; failed calls are ignored and successful non-infra calls still defeat suppression.
- BPF process-tree matching now recognizes unattended-upgrade during sensitive-file scoring, preventing unattended updates from staying High when other package-manager writes are downgraded.
- Upload PHP scoring now reuses the bounded PHP-content read result instead of re-reading clean files in full, avoiding avoidable memory spikes on large uploads.
- State prune no longer evicts internal housekeeping entries (throttle counters, per-file content-hash baselines, the baseline-complete sentinel). The prior sweep deleted them after 24 hours of unchanged content and re-armed CheckSensitiveFiles' "appeared" path on stable files like `/etc/shadow`, `/etc/passwd`, and `/etc/group`, producing spurious HIGH alerts on hosts where these files had not changed in a day.
- `sensitive_file_modified` "appeared" findings now carry a real timestamp; the prior emitter left it unset so the alert rendered the modification time as `0001-01-01 00:00:00`.
- The PHP-relay action audit log is no longer created at startup when `auto_response.php_relay.freeze` is off, while manual thaw actions still create and write their audit entry. Operators who left the safe default no longer see a permanent zero-byte `/var/log/csm/php_relay_audit.jsonl` and assume audit is broken.
- PHP-relay Path 4 (HTTP-IP fanout) now treats the host's own interface addresses and loopback as proxy-equivalent, so WordPress cron and other local server-to-server callbacks no longer page as "one source IP triggered N distinct scripts". Self IPs refresh on SIGHUP alongside the proxy CIDR list so new cPanel account alias addresses are picked up without a daemon restart.

## [3.5.1] - 2026-05-17

### Fixed

- Heavy filesystem checks (`webshells`, `php_content`, `filesystem`, `htaccess`, `file_index`, `phishing`) now get a 15-minute timeout instead of the 5-minute default, and the check-duration metric has finite buckets through that ceiling. Busy shared hosts with hundreds of WordPress installs can exceed 5 minutes walking every account's document roots, so the prior cap surfaced noisy `check_timeout` warnings and hid slow successful scans in metrics.
- `sensitive_file_modified` periodic hash-diff findings now carry the file path and a real timestamp; the prior emitter left both unset, so alerts rendered the modification time as `0001-01-01 00:00:00`.
- CI now builds the release binary with the `bpf` build tag (amd64 inline script and arm64 `build/Dockerfile.build`), so AF_ALG, exec, connection, and sensitive-file monitors load their BPF LSM backends instead of silently falling back to legacy/auditd-tail at runtime on supported kernels.

## [3.5.0] - 2026-05-16

### Added

- Database trigger / event / routine bodies are now classified Critical when they match role-escalation writes (UPDATE on `*_usermeta` granting administrator caps), magic-token gating on user-controllable profile fields, or raw `user_pass` reads. The 2026-05-15 incident shape now fires `db_malicious_trigger` instead of the generic `db_unexpected_trigger` Warning.
- After a malicious trigger that gates on `display_name LIKE '%<token>%'` is found, CSM automatically scans the WordPress users table for accounts whose display name still carries the token and emits a `db_magic_token_user` Critical finding per match, giving operators a list of accounts that may have been silently promoted.
- Cross-account administrator overlap is tracked between scans in a new `admin:emails` bucket, and emits `admin_cross_account_overlap` Warning when the same WordPress administrator email appears on the threshold number of distinct cPanel accounts (default 2, configurable via `detection.admin_overlap_min_accounts`). Catches the shared-hosting compromise pattern where a single contractor credential leak blasts across multiple customer sites.
- New `csm forensic-snapshot <account> --out <archive.tar.gz>` bundles incident-response evidence for one cPanel account: per-schema mysqldump of triggers, events, and routines; administrator roster; active session metadata; and the last-7-days file mtime list under document roots. Writes a deterministic archive plus a `<out>.sha256` sidecar; refuses destinations inside the target account's home directory and excludes credentials by design.
- `csm incidents bulk-status` previews stale incident status changes with age, last-seen, kind, domain, account, and mailbox filters. Live updates require explicit apply and confirmation flags.
- Added a production incident-response runbook covering safe upgrade, backup, forensic snapshot, credential rotation, mail queue review, stale incident cleanup, and recovery checks.

### Fixed

- Deep file indexing now preserves cached nested entries during incremental scans, preventing safe-skip loops on busy WordPress hosts.
- DB magic-token detection now requires high-entropy activation strings, avoiding Critical findings for ordinary display-name word filters.
- Forensic snapshots now discover nested WordPress roots, reject unsafe schema archive names, preserve valid cPanel database names that contain `@`, and keep account-private metadata out of the recent-file list.
- Forensic snapshots now write a manifest self-audit with discovery results, skipped-path reasons, capture counts, and the private-path exclusion policy.
- Local CI formatting now checks tracked Go source files only, so warm tool caches under the repo do not break `make ci`.
- `csm incidents list` now returns the first page by default and still offers an explicit full dump, preventing busy hosts from overflowing the local control response.
- YARA rule `backdoor_htaccess_auto_prepend` no longer fires on the generated Really Simple Security auto-prepend block, while standalone same-path directives still alert.
- YARA rule `spam_htaccess_redirect` now requires an external redirect host with an Apache redirect flag, so WordPress HTTPS-force redirects and anti-scraper `[F]` block lists no longer trip a critical alert.
- cPanel max-defer retry noise after an existing outgoing mail hold no longer opens a fresh spam-outbreak alert.
- Outgoing-mail-hold auto-suspend now short-circuits when the cPanel user already appears in `/etc/outgoing_mail_hold_users`, and the "exceeded max defers/failures" branch records the hold-seen marker so a sustained exim retry loop cannot trigger fresh whmapi1 holds every retry hour.
- Outgoing-mail-hold retry suppression now starts only after CSM confirms the hold was applied or already active, so failed whmapi1 calls keep retrying and alerting.
- Known developer or reseller administrator emails can now be marked trusted for the cross-account admin overlap check without raising the global threshold.

## [3.4.0] - 2026-05-13

### Added

- `csm doctor challenge` checks challenge public URL, TLS files, port-gate setup, webserver snippets, configtest, and the live gate endpoint.
- Status health now includes automation rollout state: dry-run block count, challenge pending count, port-gate activity, pending firewall rollback, and the last automation action.
- Production reference config at `configs/csm.yaml.production.example` covers the fields operators routinely tune (auto-response, firewall, spray suppression, retention) so a new install can start from a known-good profile.
- Incidents Grouped tab now paginates with the same page-size selector as Correlated, and both detail panels surface the current firewall block state for the incident's source IP so operators can see at a glance whether the source is already blocked.
- Generic incident-driven firewall hand-off `incidents.auto_block` blocks the source IP when any non-spray incident reaches the configured severity, catching low-and-slow attackers that never trip per-detector windows.
- ModSecurity escalation hits and window are now operator-tunable via `thresholds.modsec_escalation_hits` and `thresholds.modsec_escalation_window_min`, so paced scanners spreading denies across hours can be caught by raising the window without lowering the hit floor.

### Docs

- Credential-spray `block_at_severity` now documents the paced-attacker trap on the `critical` tier and recommends `high` for production hosts.

### Changed

- Settings restart hints now come from the same hot-reload manifest used by config diffing, and API contract tests cover the phpanel-facing status, components, email groups, and ModSecurity JSON shapes.
- Incidents Timeline Search now reads incident timelines in addition to finding history and the UI audit log, so an IP that has rotated out of the finding-history bucket but is still attached to an open or recently resolved incident still surfaces. The empty-state help text lists each data source and the retention behavior.

### Fixed

- Incident auto-block now retries after dry-run, uses a single source IP from mailbox/account incidents, and avoids duplicate firewall mutations when the legacy auto-block path already blocked the IP.
- Incidents Timeline Search now bounds finding-history reads before building the response, preventing large history windows from stalling the daemon on busy hosts.
- Challenge hardening now rejects invalid listener ports early, lets visitors retry after a failed CAPTCHA response, and keeps IPv6-only port gates from touching IPv4 entries.
- Firewall Blocked IPs view now lets operators choose and persist page size so large block lists are not capped at the first page.
- `challenge.listen_port` now rejects empty listener ports when challenge mode is enabled, while still rejecting out-of-range ports before enablement.
- `csm doctor challenge` HTTPS probe no longer type-asserts the default HTTP transport, removing a panic risk if the default is ever wrapped.
- `/api/v1/status` caches the last automation action briefly so dashboard polling no longer opens a bbolt history cursor on every request.

## [3.3.2] - 2026-05-12

Replaces 3.3.1 (tag withdrawn before public release).



### Fixed

- Firewall `smtp_block` allow-list always includes the mailnull UID alongside root. Exim's queue runner switches to mailnull for delivery, so the previous code silently dropped queued mail unless the operator remembered to list mailnull under `smtp_allow_users`. The omission caused outbound SMTP to stall in SYN-SENT until the operator manually added mailnull, so the safe default is to bake it in.
- Exim "outgoing mail hold" rejection lines no longer re-apply the hold. The rejection fires on every queued-message retry while the hold is set, so amplifying it caused a feedback loop where an operator who cleared a false-positive hold saw it reappear within seconds. cPanel's TailWatch::Eximstats stays the authoritative source; CSM still amplifies the underlying threshold trip via the "max defers and failures per hour" path and via the cloud-relay / credential-leak / compromised-account detectors when real abuse is present.
- Single direct cPanel form login from a non-infra IP no longer triggers an auto-block when `auto_response.block_cpanel_logins` is enabled. One Warning-level audit row is not brute evidence; legitimate customers logging in from a new country were getting 24h lockouts. Thresholded brute checks (multi-IP login, webmail/API brute, FTP brute) still respect the same knob.

## [3.3.0] - 2026-05-11

### Added

- New `csm webserver-integration {install|upgrade|status|validate|remove}` subcommand wires the detected webserver (Apache / LSWS / Nginx) to redirect challenge-flagged IPs to an operator-set public URL, with every change configtested before reload and rolled back on failure. The new `challenge.public_url` config field is required before install.
- New `challenge.port_gate.enabled` option installs an nftables chain that drops every connection to the challenge listener port except from loopback, operator infra_ips, and IPs the daemon has just flagged. The IP allow carries the same TTL as the challenge entry so a daemon crash cannot leave the port permanently open.
- Performance Findings page offers per-row Actions for two safe automated fixes: truncate a bloated error_log in place (preserves the inode) and disable display_errors by commenting the directive and appending an Off override at end of `.user.ini` / `php.ini` / `.htaccess`. Admin-only, sandboxed to per-account web roots; symlinks and unsupported file types are refused.
- Credential-spray super-incidents can hand the source IP to the firewall once the spray trips or escalates to CRITICAL. New `incidents.spray_suppression.block_at_severity` knob (`""`, `high`, `critical`); defaults to detection-only so existing operators see no behavior change. `auto_response.dry_run` and `block_ips` still gate the actual block.
- Dashboard right rail gains a Components matrix listing every registered watcher with its attached state, time since last state change, and the most recent finding it produced. New /api/v1/components endpoint backs the view; read-scope tokens can call it.
- Performance load check now also flags sustained pressure: when the 5-minute and 15-minute load averages both exceed 70% of the high threshold (even though the 1-minute load is calm) a Warning is emitted. Catches the "load 9 on 40 cores for 15 minutes" shape that a spike-only check misses.
- Redis config check now reports used-memory headroom against maxmemory: Warning at >=80%, High at >=90%. Operator-meaningful signal for instances that approach eviction churn or OOM-error territory.
- The incident correlator auto-resolves stale Open and Contained incidents once an hour using per-kind idle thresholds (default 24h for mailbox takeover and credential spray, 7d for web-account compromise; host-level kinds never auto-close). Resolved-by-auto incidents carry `closed_by: "auto:stale"` and an `incident_auto_closed` timeline action so reporting can distinguish them from operator closes; the new `incidents.auto_close` config block lets operators disable, dry-run, or retune the thresholds.
- New credential_spray super-incident kind collapses one source IP brute-forcing many distinct mailboxes inside the merge window into a single incident keyed on the source IP, instead of one mailbox_takeover per attacked username. Default OFF + dry_run TRUE so the path ships dark; counters under csm_credential_spray_* report what would have happened. Whitelisted IPs are skipped. Flip via the new incidents.spray_suppression config block.
- New /api/v1/incidents/groups endpoint and a Grouped tab on the Web UI Incidents page bucket open / contained incidents by (kind, source) so a host with thousands of per-mailbox incidents browses as a handful of attacker-IP rows. Read-scope eligible; grouping caps at 10000 matching incidents per call.
- Web UI Audit, Quarantine, Cleanup History (file + DB tabs), and Threat Intelligence Top Attackers card now use the shared csm-toolbar pattern instead of hand-rolled card-action filter rows; bulk-action buttons live in the toolbar's actions slot until the page-specific selection bar replaces them.
- Web UI ModSecurity page is rebuilt as a workbench: status strip across the top, an Active WAF pressure summary list (top attackers by hits) on the left, top rules / domains / status counts on the right, and Blocked IPs / Events / Rules tabs below. Block detail panels surface first-seen, top URIs, sample events, and direct links to threat intel, firewall lookup, and rule management. Long URIs are middle-truncated so they no longer stretch the page.
- Web UI Email page is rebuilt as a workbench: a compact status strip replaces the six-card stat row, the first viewport leads with grouped action rows (compromised, spam outbreak, auth failure, queue, malware) on the left and mail protection state on the right, and the raw findings, auth-failure clusters, queue, quarantine, and top senders move into tabs below. Quarantine renders full width with row-card fallback on narrow screens.
- New /api/v1/email/groups endpoint returns server-side grouped action rows (compromised account, spam outbreak, auth failure, queue alert, malware) over a bounded history window so the upcoming email workbench does not fan out into thousands of in-browser pivots. Read-scope tokens may call it; the endpoint never mutates state.
- /api/v1/modsec/blocks gains additive fields (first_seen, last_seen_iso, top_uris, domain_count, sample_events) so the upcoming WAF workbench can drive the detail panel from one round trip; existing JSON keys keep their previous semantics. modsec stats, blocks, and events GET endpoints now accept read-scope tokens.
- Web UI gains three more shared layout primitives -- a richer toolbar, a grouped summary-list for high-volume action rows, and middle-truncated text -- and CSM.Table now exposes sticky headers, external page-size selects, decoupled result-count targets, and row-click hooks. Used by the upcoming Email and ModSecurity workbench redesigns; the previous filter toolbar class is renamed to csm-toolbar.
- Web UI ships a set of shared layout primitives (page header, status strip, action queue, filter toolbar, empty state, sticky action bar, detail panel, danger zone) and small JS helpers used by upcoming page redesigns; existing pages render unchanged.
- Web UI navigation is reorganised into a workflow-grouped sidebar (Overview, Triage, Response, Operations, Configuration); URLs are unchanged, groups remember their collapsed state, read-scope views hide admin-only entries, and the sidebar collapses into a drawer on tablet/mobile viewports.
- Web UI dashboard leads with a priority queue (open incidents plus top critical/high findings) and a system-posture chip row; the analytics charts and recent activity feed remain available below the fold.
- Web UI Findings page moves the on-demand account scan into a modal, opens row details in the shared side panel instead of expanding the table, moves grouping to a header view toggle, and surfaces bulk fix/dismiss in a sticky action bar that appears once a row is selected.
- Web UI Firewall page is split into Overview, Lookup, Blocks, Allow Rules, Configuration, Audit, and Danger subviews addressable via /firewall?view=<name>; the Flush blocked IPs action moves into the Danger zone with a stronger confirm dialog, and the Configuration tab links into Settings instead of duplicating the editor.
- Web UI Settings sidebar gains free-text search across section titles, field labels, and YAML keys, and the Firewall and Threshold sections render their fields inside topic-named fieldsets (Access ports, Rate limits, Flood protection, Geo and DynDNS, SMTP controls, Logging, Limits, IPv6; Scan intervals, Mail brute force, SMTP brute force, Account spray, State retention) instead of one flat grid.
- Settings validation errors now highlight the affected field, restart notices name the changed section, the save bar stays visible while scrolling, and secret inputs use an explicit set-new-value action.
- Web UI Email, Threat Intelligence, Quarantine, Cleanup, Rules, ModSecurity, ModSec Rules, Audit, Performance, Hardening, Settings, Incident, and Account pages adopt the shared page header so every operator surface has the same title, icon, subtitle, and action area; the Hardening and ModSec Rules empty states now use the shared empty-state layout.
- The incident correlator can return a paginated, status-filtered page of incidents in one call; the web UI and phpanel can now scroll through long incident lists without loading the entire set.
- The incident list endpoint accepts limit, offset, and status query parameters and returns an envelope with the page total when those are present; calls without query parameters keep returning the existing bare-array shape so existing webhook and SIEM consumers see no diff.
- The incident page now paginates server-side with a configurable page size (25/50/100/200) and a footer showing the current range and total; only the visible page is fetched, so long incident lists no longer slow the table render.

### Changed

- Challenge listener now binds to `127.0.0.1` by default; webserver-integrated direct redirects require `challenge.listen_addr: 0.0.0.0` and a `challenge.public_url` ending in `/challenge`. `challenge.port_gate.enabled` can keep the public port limited to flagged IPs and operator infra.
- Incidents Grouped tab no longer caps its content panel at 480 px with an inner scrollbar. On hosts with thousands of groups the previous layout showed only the first eight rows inside a small box; the list now flows to its natural height and the page scrolls normally.
- Performance Findings rows render the remediation as a single button per row; the card header gains a Bulk fix dropdown that applies the matching action across every affected row of a check type with one confirmation.
- Dashboard drops the Recent activity feed and the duplicate Fanotify / Signatures / log-watchers chips; runtime watcher state and feature flags now live in one Components card. Desktop critical-finding notifications still fire.
- Firewall page drops the dedicated Lookup tab. The Inspect IP form on Overview now renders the lookup result inline below it; per-row Inspect buttons in Blocks, Allow Rules, and Audit jump back to Overview instead of a second copy of the same form.

### Fixed

- Challenge webserver integration now renders snippets from the configured challenge port, keeps no-op upgrades stable, writes Apache/LSWS and Nginx maps to webserver-readable runtime paths, validates direct public URLs, and opens the listener in CSM firewall when port-gate is enabled.
- Challenge server now serves HTTPS when `challenge.tls_cert` + `challenge.tls_key` are set, and direct/public listeners can fall back to `webui.tls_cert` / `webui.tls_key`. Loopback listeners stay plain HTTP by default.
- Challenge routing no longer targets post-auth audit events (cPanel/webmail logins, file uploads, multi-IP login, WHM) or non-browser protocols (SSH, FTP, DNS recursion, outbound, API). Customers logging in from non-trusted countries no longer get hard-blocked 30 minutes after a normal cPanel login.
- A daemon restart no longer orphans an open credential_spray incident and opens a duplicate super-incident for the same attacker IP. On startup the spray detector's in-memory binding is rehydrated from the persisted open incidents, so the suppress path keeps routing new findings into the existing incident instead of re-tripping at the distinct-mailbox threshold.
- Credential-spray firewall hand-off now re-evaluates on every merged finding instead of only at the severity-transition moment. An operator who arms `block_at_severity` after an incident has already reached the configured severity now gets a block on the next matching finding rather than waiting for the attacker to open a fresh incident.
- Performance remediation actions now honor configured account roots, clear fixed rows immediately, and fail closed if the target file changes during the edit.
- Shared detail panel now closes on Escape and on click anywhere outside it; the X button was the only way to dismiss before.
- Firewall page drops the disabled "Unblock selected IPs" button on the Danger subview; per-row Unblock and Flush blocked IPs cover the workflow.
- Credential-spray firewall hand-off now wires after firewall startup and releases the incident lock before calling the firewall. The auto-response gate is checked at block time so SIGHUP changes to `enabled`, `block_ips`, or `block_expiry` apply to spray blocks too.
- `systemctl restart csm` no longer waits 30 to 60 seconds. The sd_notify READY signal and the systemd watchdog notifier now fire as soon as the real-time watchers and control surfaces are attached, instead of blocking on the initial baseline scan and the kernel-state probes. The baseline scan still runs inline and the alert dispatcher remains gated behind it.
- Auto-block now hard-blocks only confirmed attacker-IP mail findings and keeps single mailbox auth failures, account-spray visibility findings, and account-only mail alerts out of firewall action. This avoids blocking a legitimate user after one failed login while preserving thresholded brute-force blocks.
- PHP content scanner no longer flags legitimate WordPress plugins that fetch upstream resources from github (wp-statistics GeoLite2 updates, unyson font fetcher, polylang language packs). The "remote URL co-present with file_put_contents/fwrite" indicator was a co-presence across a 32 KB window that is too weak to stand alone; the same-line variant is preserved as a strong signal.
- PHP content scanner no longer flags themes and page builders for dynamic-CSS/HTML construction. The standalone "concatenation count > 30" indicator caught Sydney theme `inc/styles.php`, Elementor, Beaver Builder and dozens of other legit code paths. The combined "hex strings + concatenation" branch still catches real function-name obfuscation.
- Phishing directory heuristic no longer flags developer tutorial dumps whose HTML is a benign credential form. The fast-pass content check now parses normal HTML attribute spacing and requires a credential input plus a phishing-kit signal, so trivial demo logins, contact forms, and password-reset stubs drop out without consulting any path-name allowlist.
- Dashboard moves the Fanotify state chip out of the runtime-telemetry status strip into the System posture capability row alongside Firewall, Auto-response, Email AV, Threat Intel, Signatures, and Challenge. Top strip now carries only runtime telemetry (uptime, last critical, log watchers, signatures); bottom row carries capability state.
- Dashboard Components now attributes activity only to live watcher findings, ignores stale latest findings outside the lookback window, and registers PAM listener state.
- Disabled scheduled checks now clear their prior active findings on the next scan while throttled checks still keep their last valid findings. Dashboard posture severity tiles now wrap safely in narrow side rails.
- Performance findings (PHP handler, MySQL/Redis config, error-log bloat, WP config / transients / cron) no longer disappear between deep scans. The 60-minute throttle is now enforced by the runner, and a throttled cycle leaves the previous findings in place instead of having the scan purge list wipe them.
- Dashboard right rail now carries the runtime status chips and 24h severity totals inside the System posture card, so the column next to a long priority queue stops sitting empty.
- Incident auto-close and grouped incident views now avoid close-sweep races, cap after filters, and roll mailbox fan-out up by observed attacker IP.
- The shared detail panel close button now always closes the panel; some Tabler bundles did not wire Bootstrap's data-bs-dismiss handler on the dynamically mounted offcanvas, leaving the X button inert on the Incidents and ModSecurity pages.
- Dashboard now lets the system-posture card hug its content instead of stretching to match the priority-queue column on hosts with many open incidents.
- Email and ModSecurity workbenches cap the grouped action / WAF pressure list height with an internal scroll so a long list does not push the rest of the page far below the fold.
- ModSecurity blocks page no longer drops the GeoIP enrichment with HTTP 400 on hosts with thousands of unique attackers; the request is chunked client-side to stay under the 500-IP server cap.
- Email and ModSecurity workbench filters now keep same-day results, grouped rows, queue status, and WAF event ordering consistent with the selected window.
- Dashboard priority queue refresh no longer stops chart startup, and incident queue links now open the targeted incident in the shared detail panel.
- State directory migration, firewall audit log, and ModSecurity overrides include now surface close errors instead of silently dropping the last write on disk-full or fsync failure.
- The /incident "Correlated" tab no longer stays empty on busy hosts. Realtime detectors (dovecot/exim auth failures, ssh/ftp logins, ModSecurity, WP/XML-RPC/admin-panel brute force, cPanel File Manager, WHM, webmail, PAM, cloud-relay, rate limits) now populate `SourceIP`/`Mailbox`/`Domain`/`TenantID` on findings so the incident correlator can group them; previously these structured fields were empty and `KeyFor` silently dropped every finding. `KeyFor` also accepts `CPUser` as a fallback account so php-relay findings correlate.
- Mail findings against cPanel-local mailboxes (no @domain) now correlate by account; previously some paths opened one incident per attacker IP.
- Mailbox auth and abuse incidents are labelled "mailbox takeover" instead of "web account compromise"; domain-level mail checks and PHP relay keep their account-compromise kind.
- ModSecurity findings no longer record the served vhost name when the vhost is a bare IP address; this prevented unrelated raw-IP-served sites from being merged into one incident.
- Single-finding scanner probes and isolated mistyped passwords no longer open an incident on the first event; the correlator now requires a second correlated finding within the merge window before opening, while Critical-severity findings still page on the first hit.
- Incident pagination now uses stable ordering, copies only the visible page, and sends the browser back to the last valid page when a filtered result set shrinks.

## [3.2.0] - 2026-05-09

### Added

- Web UI Settings has a new Firewall section. Saving warns when the WebUI port is about to fall outside the allowed inbound list so operators see the lockout risk before the restart applies.
- Firewall settings can now be applied with a rollback timer, then confirmed or reverted from the Web UI or CLI before the timer expires.

### Changed

- Firewall defaults: opened TCP 853 (DNS-over-TLS) and UDP 853 (DNS-over-QUIC) inbound and outbound, added DCC/Pyzor outbound UDP so SpamAssassin network checks do not silently fail, and bumped `conn_rate_limit` to 200/min and `conn_limit` to 400 to tolerate shared CGNAT egress. SSH (22) stays out of the default port list; uncomment the sample line in `csm.yaml` if sshd listens on 22.

### Fixed

- ModSecurity escalation no longer auto-blocks IPs whose only matches are log-only WAF rules on LiteSpeed hosts. The detector now consults each rule's declared action so pass-action vendor rules stop driving false 24-hour bans.

## [3.1.0] - 2026-05-08

### Added

- Web UI shows a top banner when a newer CSM release is available upstream; the daemon polls GitHub daily and falls back to the OS package manager but never applies the upgrade itself. Set `updates.check_enabled: false` to disable on air-gapped hosts.
- Optional in-kernel cgroup-deny enforcement for matched outbound connections, gated on Phase 3 detectors and per-host safe-UID map. Default off, dry-run on; operators flip after telemetry review.
- The Web UI now has a cleanup history view for file backups and dropped database-object backups.
- Optional `process` field on findings and audit events carries PID/PPID/UID/user/account/exe/sanitized cmdline plus parent chain (depth 5). Omitted when no context is available; existing webhook consumers see no schema change.
- Operators can now exempt specific mailboxes or whole domains from the cloud-relay credential-abuse detector only, without weakening the rate detector for the same account.
- Incident correlation groups related findings into one story per account, mailbox, or process. New API + CLI surface plus persistence; original findings stream is unchanged.
- Direct SMTP egress detector flags non-MTA local processes opening outbound mail-port connections, with a platform-resolved MTA allowlist and rDNS enrichment.

### Changed

- Bumped Go module dependencies: `yara-x/go` 1.15.0 → 1.16.0, `sentry-go` 0.45.1 → 0.46.2, `klauspost/compress` 1.18.5 → 1.18.6, `oschwald/maxminddb-golang/v2` 2.1.1 → 2.2.0, `mdlayher/netlink` 1.11.0 → 1.11.1.
- Bumped builder image YARA-X C library to v1.16.0 (`glibc-2.28-r5`) to match the Go binding upgrade and provide the new `yrx_compiler_max_warnings` symbol.
- Pinned `github/codeql-action` workflows to v4.35.3.

### Fixed

- Update banners now receive the release-check status payload and no longer treat post-tag builds as older than their base release tag.
- `smtp_probe_abuse` finding details now report that auto-block is scheduled with the configured `auto_response.block_expiry` (default 24h) when live auto-blocking is enabled, instead of contradicting the runtime by saying "consider auto-block".
- Hardened Web UI rendering for attacker-controlled fields and fixed bulk selection on the Threat Intel page.
- Settings navigation now comes from the backend schema, and missing templates return an error instead of panicking.
- `renderTemplate` now buffers output before flushing so a template execution failure surfaces a clean 500 instead of a partial 200 body, and the settings UI drops a dead `resp.ok` branch that became unreachable after the `CSM.request` refactor.
- Incident correlator rejects unknown status strings, the webui POST `/api/v1/incidents/{id}/status` mutator is now CSRF-protected, and a daily retention sweep prunes resolved/dismissed incidents older than 30 days and bumps `csm_incidents_compacted_total`.
- Incident correlation now survives daemon restart for process-only and remote-IP incidents, pruned incidents disappear from live API/control results, and pre-alert filtered findings still join incidents.
- The Incidents web UI now lists correlated Incident objects, opens their merged timeline, and keeps the older IP/account timeline search in a separate tab.
- The Firewall entry in the Response menu now renders an icon to match the other dropdown items.
- The Performance dashboard MySQL card now shows `n/a` instead of `0 conn` when csm cannot query MySQL, and the daemon under systemd can finally read its local mysql credentials so connection counts and MySQL configuration findings appear instead of silently dropping.
- Direct SMTP egress now honors its detector backend setting, validates configured ports, and still reports hosted processes that use MTA-looking names.
- BPF enforcement now honors global, detector, and kernel dry-run layers, rejects incompatible legacy-only backend settings, and reports active only when the connection tracker is actually running on BPF.

### Documentation

- Copy Fail BPF docs now describe the shipped kernel-side blocking behavior and validation steps.

## [3.0.0] - 2026-05-06

### License

- **CSM is now AGPL-3.0-or-later.** v2.x releases remain MIT; v3.0.0 onward is AGPL. Running unmodified CSM to protect your own hosting servers — including commercially — has no new source-disclosure obligation. Redistributing CSM (binary or source) or running a *modified* version that users interact with over a network triggers the AGPL's source-availability requirements (section 13). The license change is the reason for the major version bump; there are no breaking config or API changes in this release.

### Added

- Internal BPF scaffolding: shared backend coordinator, kernel capability probe, and ringbuf consumer used by upcoming kernel-side detectors. Operators see BPF capability entries in `/api/v1/capabilities` only on bpf-tagged builds whose kernel accepts the relevant probes.
- Live outbound-connection tracker built on BPF cgroup hooks. On bpf-tagged builds with cgroup v2, suspicious user connections produce findings the moment the kernel sees them instead of on the next periodic scan; older kernels keep using the existing scan.
- Top-level `disabled_checks` lets a host skip whole scheduled check categories entirely; `alerts.email.disabled_checks` still only suppresses email.
- `smtp_probe_abuse` tracks raw inbound SMTP connect rate per source IP from Exim mainlogs, catching scanners that disconnect before AUTH. Default threshold is 100 connects in 5 min/IP; setting it to `0` disables the signal.

### Changed

- AF_ALG live-monitor backend selection is also published through the shared BPF backend telemetry while the existing AF_ALG metric remains available for current dashboards.
- The outbound-connection check policy is now a pure function shared between the live tracker and the periodic safety-net check, so both code paths produce identical findings.
- AF_ALG (CVE-2026-31431) live monitor now denies the syscall in the kernel itself on hosts with BPF LSM, instead of reacting after the fact via the audit log. Hosts without BPF LSM keep the audit-listener fallback unchanged.
- Live process-exec monitor built on a sched tracepoint. Suspicious processes started from world-writable paths or with masquerading kernel-thread names are reported the moment they appear, instead of waiting for the deep periodic scan; older kernels keep using the existing scan.
- Live sensitive-file write monitor built on BPF LSM. Writes to existing sensitive files are reported when the kernel sees them, and newly-created drop-ins are reported during watchset refresh; older kernels fall back to a periodic content-hash check covering the same paths.

### Fixed

- YARA Forge automatic updates now require an explicit signed ZIP mirror URL, avoiding repeated verification failures against unsigned upstream GitHub assets. PHP Shield now installs across every detected cPanel EA-PHP version and writes events to a dedicated log path that PHP users can reach.
- `port_flood` firewall rules are now rate-limited per source IP, per port, and per IP family instead of globally. SMTP defaults raised to 600 hits / 300 s (= 120 conns/min/IP) so normal MUA bursts pass without dropping legitimate sessions when one noisy source is on the network.
- `conn_limit` default raised from 50 to 300 (matches CSF `CT_LIMIT`) so power users with multi-tab webmail, IMAP IDLE on several devices, and parallel SMTP send do not silently lose new connections when their concurrent count peaks. Existing installs keep their configured value; only fresh installs and unconfigured fields pick up the new default.
- `user_outbound_connection` no longer false-positives on the accept side of inbound connections (e.g. pure-ftpd PASV data channels, user-owned daemons listening on high ports), and emitted findings now carry a real timestamp instead of the zero value.
- ModSecurity deny events now escalate repeated blocked requests from the same IP into auto-block decisions, not only CSM-owned ModSecurity rules.
- Auto-blocked IPs and subnets now take effect for existing keep-alive traffic, avoid repeated subnet block churn, and keep active findings from accumulating stale scan results.
- `waf_rules` no longer false-positives during cPanel's nightly `modsec_assemble` window; on cPanel+LiteSpeed the rule probe is re-tried once after a short delay before alerting, so a real "no rules" host still alerts in the same scan.
- `disabled_checks` now accepts finding names such as `waf_rules` and `suspicious_crontab`, so UI selections disable the matching check runners.
- Packaged builds now include journald mail-log support used by the phpanel profile on hosts without mail log files.
- Revolution Slider exploit detector no longer fires on premium WooCommerce themes that integrate with RevSlider; the signature now requires the actual exploit token pair, not just substring co-occurrence.

## [2.12.0] - 2026-05-05

### Documentation

- README now leads with operator problems, quick install paths, safety defaults, and a shorter CVE pointer.
- Docs now cover config drop-ins, FHS state migration, daemon health, dry-run blocking, verdict callbacks, scoped tokens, event streaming, and threat-intel sources.
- A new CVE mitigations page explains current hardening coverage and live detection behavior.

### Added

- AF_ALG (Copy Fail) live monitor now runs through a backend coordinator that prefers BPF LSM when the kernel supports it and falls back to the existing audit-log inotify listener otherwise. Build with `make BPF=1` (or `go build -tags bpf`) to compile in the BPF path; default builds continue to ship only the audit listener. This release lands the kernel capability probe (Phase A); the in-kernel blocking program is staged behind `errBPFPhaseBPending` and will activate once Phase B + alma9 integration test land — until then `-tags bpf` builds still use the audit listener, so detection coverage is unchanged.
- `detection.af_alg_backend` config knob (`auto` / `bpf` / `auditd` / `none`) overrides the live-monitor coordinator's automatic choice. `auditd` is the kill switch for a misbehaving BPF-tagged release: revert without rebuilding by editing `csm.yaml`. `bpf` enforces strict mode — no audit fallback if BPF is unavailable, useful where the operator wants kernel-side blocking or nothing.
- `csm_af_alg_backend{kind="bpf-lsm"|"auditd-tail"|"none"}` Prometheus gauge exposes which backend the coordinator selected at startup, so dashboards can see the active live-detection path without parsing logs.
- Config drop-ins are now merged on top of the active main config in lexicographic order. Automation can own its own fragment without touching the operator's main file.
- Shipped integration profile at `/usr/lib/csm/profiles/phpanel-agent.yaml` for phpanel-server-agent hosts. It sets `/var/www/*` account roots without touching the main config file.
- `/api/v1/status` returns full health snapshot (watchers, severity counts, store health, blocklist size, capabilities, version) and `/api/v1/capabilities` lists supported features for orchestrator feature-detection.
- `csm status --json` and `csm doctor` for machine-readable health diagnostics. Doctor emits suggested-fix strings for each failed check.
- `csm config schema --json` prints a JSON Schema reflected from the Config struct so external tools can validate `csm.yaml` overrides.
- sd_notify integration: daemon signals `READY=1` after startup and the existing watchdog notifier remains. systemd unit declares `Type=notify`, `NotifyAccess=main`, `TimeoutStartSec=120`.
- Phpanel webhook type (`type: phpanel`, `per_finding: true`) signs each request with HMAC-SHA256 over the raw JSON body in `X-CSM-Signature`.
- `/api/v1/events` Server-Sent Events stream: clients with a read-scope token receive each finding as it dispatches.
- `webui.tokens:` multi-credential model with `scope: admin | read`. Admin tokens still work everywhere; read tokens authorize `/api/v1/*` GETs only. Legacy `webui.auth_token:` is migrated automatically.
- `tenant_id`, `domain`, `mailbox` fields added to JSONL audit events and the `Finding` JSON for downstream correlation.
- `mail_logs.source: file|journal|auto` lets the daemon read postfix/dovecot from systemd-journald on hosts without rsyslog. Journal reader is gated by the `journal` build tag.
- `thresholds.mail_brute_account_key` - pluggable per-account extractor (builtin patterns or operator-supplied regex) for hosts with virtual mailboxes.
- Rspamd threat-intel source: `reputation.rspamd.enabled` adds per-IP rolling-history signals to attacker scoring. Token resolves from `token_env` at query time so rotation does not require a restart.
- `reputation.upstream` - HTTP threat-intel source. Agents in a fleet can share one panel-side cache of AbuseIPDB / proprietary scores; CSM caches each lookup locally for `cache_ttl_min` (default 15m) so the upstream takes O(1) hits per IP per agent. Wire contract: `docs/upstream-threat-intel-contract.md`.
- `auto_response.verdict_callback` - advisory HTTP hook called before each auto-block. Phpanel can downgrade the verdict to `allow` (audit-only) or attach `tenant_id` attribution; CSM fails open on hook errors. Wire contract: `docs/verdict-callback-contract.md`.
- Shipped `csm-prestart.example.conf` systemd drop-in template at `/usr/lib/csm/profiles/`. Operators wanting a pre-start hook use `systemd` drop-ins rather than a CSM-specific hook directory; recipe at `docs/operator-systemd-dropins.md`.
- `auto_response.dry_run` - when true (or unset; safety default), CSM logs every IP it would have blocked but does not touch nftables. Dry-run blocks are recorded to bbolt and the count surfaces in `/api/v1/status` so operators can verify the policy before flipping live. Manual operator commands bypass via `BlockIPForce`.
- `infra_ips_unresolvable` finding fired when a hostname in `firewall.dyndns_hosts` has not resolved within the grace period (default 10m). Auto-cleared when resolution recovers.
- `csm backup <archive>` and `csm restore <archive>` - tar.gz bundling of `csm.yaml`, `/etc/csm/conf.d/`, and the state directory for clean DR snapshots. Restore rejects path-traversal entries.

### Changed

- Main config now prefers the FHS config location while keeping the old path as a fallback and compatibility link during upgrades.
- State directory default now uses the FHS state location. Hosts without an override copy legacy state on first daemon start.
- systemd unit declares `StateDirectory=csm` and `ConfigurationDirectory=csm` so systemd manages permissions and ownership.

### Fixed

- Package config-path migration no longer mistakes a real config with a cleared legacy `webui.auth_token` for a fresh shipped placeholder, so reinstalling on a host that uses scoped `webui.tokens` no longer risks overwriting the operator's config.
- Postinstall no longer regenerates the WebUI auth token on every reinstall or upgrade. Token generation is gated to fresh placeholder configs, so operators on scoped `webui.tokens` with an empty legacy `auth_token` keep their existing config hash and CSRF secret across package updates.
- Postinstall no longer tightens the binary directory's permissions during install or upgrade, so non-root users can still invoke `csm` subcommands.
- Verdict callbacks now run only after local firewall safety checks, honor SIGHUP updates, and reject malformed or oversized callback responses.
- Upstream threat-intel now validates URL and timeout settings, rejects malformed cache responses, and keeps the phpanel profile's rspamd and upstream settings in one reputation block.
- CSM now resolves system commands from standard sbin directories when systemd starts the daemon with a narrow PATH, preventing false missing-command health alerts for tools like auditctl.
- Backup and restore now reject unsafe archives more strictly and avoid including or overwriting their own source files. Dry-run blocking keeps the same safety checks as live blocking, and the dynamic-DNS guard reports startup resolution failures as Warning findings.
- PHP relay shutdown now flushes its message-index writer before closing state.
- Health snapshots no longer mark disabled or not-applicable watchers as failed. `csm doctor --json` now returns JSON for config and daemon-status failures.
- Config schema output treats defaulted fields as optional and renders duration values as strings.
- Phpanel runtime secrets are no longer shipped as active profile placeholders, and validation/redaction now understands scoped WebUI tokens and phpanel webhook HMAC secrets.
- Long-lived findings (e.g. `db_rogue_admin` for a legitimate WP admin sitting in the 7-day query window) no longer re-alert on every deep tick once the 24-hour dedup window expires. `Store.MarkAlerted` now refreshes `AlertSent` for each dispatched finding, so the next tick suppresses again instead of emitting hourly until the underlying row ages out.
- Copy Fail (CVE-2026-31431) live listener and periodic check no longer fire a Critical false positive on every CSM restart. The audit-log parser now requires `type=SYSCALL`; previously any line containing the rule's key string matched, including the `CONFIG_CHANGE op=add_rule` records auditd writes when CSM redeploys its ruleset.
- CI: annotate six gosec findings in the email PHP-relay code paths (G115/G204/G304/G302) with operator-trust justifications matching the rest of the codebase. No behaviour change.

## [2.11.0] - 2026-05-01

### Added

- Email PHP-relay protection: a real-time watcher on the outbound mail spool flags WordPress contact-form spam relays and freezes the offending script's queued mail. Operator CLI to inspect, dry-run, ignore, and thaw; disabled on non-cPanel hosts.
- Copy Fail (CVE-2026-31431) detection: live audit-log listener flags any attempt to open the vulnerable kernel crypto socket from a non-system UID at Critical. Auto-skipped on hosts where the kernel isn't exploitable.
- `csm harden --copy-fail` blacklists the vulnerable Copy Fail kernel modules and unloads them. Refuses on kernels where those modules are built in, since the blacklist would have no effect there.
- `csm harden --copy-fail-seccomp` is the built-in-kernel mitigation: installs systemd seccomp drop-ins for the units that spawn untrusted code so worker processes cannot reach the vulnerable syscall. Reversible via `--remove`.
- `auto_response.copy_fail_kill_process: true` SIGKILLs the offending process when the live listener catches a Copy Fail attempt. Default off (alert-only).
- `auto_response.disable_enforce_af_alg: true` suspends the periodic re-assertion of the Copy Fail module blacklist without removing the hardening marker.
- Hardening audit reports `pass` for Copy Fail only when the host is genuinely mitigated (module blacklisted, built-in kernel with seccomp drop-ins, or KernelCare livepatch). Otherwise reports `fail` with a Fix string pointing at the real options.
- Daemon self-heals its auditd rule file on startup if it has drifted from the embedded copy. Closes the upgrade gap where a new binary shipped without re-running the postinstall, leaving Copy Fail detection silently inactive.
- CVE-2026-41940 (cPanel/WHM auth-bypass) detection in the access-log path: non-infra WHM login attempts surface at Warning (suppressible alongside other cPanel logins); the tokenless WHM-script request the published exploit uses for cache promotion surfaces at Critical, always on, and feeds auto-block.

### Changed

- Outbound-email content scanning now uses the shared cPanel-Exim spool parser, replacing a loose RFC 5322 fallback that never matched real Exim spool output.

### Fixed

- `.htaccess` user-agent cloak detector stops firing on the canonical multi-line "bad bots" snippet, where each scraper UA sits on its own RewriteCond paired with one terminal redirect. Targeted one- or two-cond cloaks still fire.
- Shell dropper detector ignores `curl ... | sh` patterns that sit inside a `#` comment, so distribution installer headers (rustup-style usage banners) no longer trip it. Real droppers on actual code lines still match.

## [2.10.0] - 2026-04-28

### Fixed

- Tightened five YAML and three YARA malware rules that fired on stock WordPress plugin code (PHPMailer, UpdraftPlus, Elementor Pro, Pro Elements, ACF). Each now requires its discriminator regex to match.
- Realtime "PHP in uploads" warning suppressed on cPanel restore staging duplicates and WP-Optimize probe files. Signature/YARA scans still run.
- `wpcheck` caches wp.org 404s for 72h so plugins absent from the repo (paid forks, internal plugins) stop driving the 4-attempt retry storm.
- Outdated-plugin findings aggregated per site instead of per plugin, so the deep-tier alert channel no longer saturates on hosts with many sites.
- Fanotify analyzer absorbs cPanel-restore-grade event bursts: bigger buffer, larger dirty-region tracker, eager reconcile when drops cross threshold mid-tick.
- Three `.htaccess` detectors stop firing on legitimate plugin shapes: targeted-filename FilesMatch blocks, negated/bot-blocklist UA conditions, and same-brand ErrorDocument redirects.
- Deep-scan "new PHP in uploads" finding shares the cPanel-restore and WP-Optimize recognisers with the realtime path.

### Added

- Cleanup-history API: list and rollback endpoints for MySQL persistence drops (`/api/v1/db-object-backups`, `/api/v1/db-object-backup-restore`). Browser-side tab to follow.
- Hardened `.htaccess` pre_clean backups now show up in the existing quarantine listing and roll back through the same handler. Sidecar metadata format aligned with the rest of the codebase.
- OpenCart database content scanning: settings, product/info descriptions, and admin user table. Three new finding categories.
- Magento 1.x and 2.x database content scanning (XML for M1, PHP-array for M2): config, content, and admin tables. Three new finding categories.
- Drupal 8+ database content scanning: config, article bodies, administrator role membership. Three new finding categories.
- Joomla database content scanning: extensions params, articles, Super User accounts. Three new finding categories.
- WordPress multisite database scanning: secondary blog tables scanned alongside the unprefixed main-site tables when `MULTISITE` is declared.
- Signature-update-driven retroactive deep rescan: a daemon watcher arms a full-tree sweep when any rule file's mtime advances. New metric, finding name, and `detection.rescan_on_signature_update` toggle.
- MySQL persistence-mechanism scanner: audits triggers, events, stored procedures, and stored functions. Operator-driven cleanup via `csm db-clean --drop-object` with full CREATE-SQL backup; new allowlist knob suppresses the Warning tier.
- Hardened `.htaccess` audit emits seven per-pattern findings. New `auto_response.clean_htaccess` flag auto-cleans flagged files with backups retained.
- `csm store export <path>` writes a tar+zstd backup of bbolt + state + signature cache, with a `.sha256` companion for verification.
- `csm store import <path>` restores a backup onto a stopped daemon. Partial restore via `--only=baseline|firewall`; cross-platform restore refused unless explicitly forced.
- Challenge bypass paths: Cloudflare Turnstile / hCaptcha for JS-disabled visitors, signed-cookie operator sessions, and verified search crawlers via reverse-DNS forward-confirm. All opt-in.
- Audit-log export ships every deduplicated finding to JSONL and/or RFC 5424 syslog. `csm export --since` backfills historical findings for first-time SIEM onboarding.

## [2.9.0] - 2026-04-27

### Fixed

- Tightened 10 YAML detection rules to require their discriminator regex (proximity / co-occurrence in the same expression) instead of letting loose substring tokens accumulate to `min_match`. Affected: `webshell_wp_fake_plugin`, `exploit_wp_admin_creation`, `wp_cron_backdoor`, `network_port_scanner`, `spam_conditional_googlebot`, `backdoor_ssh_key_injection`, `dropper_telegram_exfil`, `dropper_php_input_stream`, `obfuscation_compact_unpack`, `deface_owned_by`. Stops FPs on Yoast SEO, Elementor importer, Monolog handlers, Jetpack/Mobile_Detect UA libs, phpseclib RSA/Blowfish, WPML translation API, and SmartBill REST client. `exploit_wp_admin_creation` also catches the multi-statement form (`wp_create_user(...); $u = new WP_User(...); $u->set_role('administrator')`) used by hardcoded backdoors. `exfil_archive_send` (YAML+YARA) accepts the namespaced `new \ZipArchive` form too.
- Tightened 3 YARA rules to require proximity between signal terms: `miner_hidden_iframe` (was matching `marginwidth="0"` on WP oEmbed iframes), `deface_owned_by` (Google API field docs / PhpDocReader / WooCommerce CLI), `exfil_archive_send` (Elementor template export). All three now require build/heading/sink to co-occur in the same proximity window.
- `webshell_realtime` filename map (`shell.php`, `c99.php`, etc.) now requires content corroboration -- a request superglobal piped into a code-execution primitive, or eval/assert wrapping a base64/gzinflate decoder. Stops FPs on WP-bundled Pear `Text_Diff/Engine/shell.php`.
- `php_in_uploads_realtime` is content-aware: webshell markers stay Critical, clean PHP in uploads downgrades to Warning. Stops FPs on TinyMCE `smile_fonts/charmap.php` and similar bundled assets. Now also taint-tracks the indirect form (`$cmd = $_GET[..]; system($cmd);`) and emits `webshell_content_realtime` for content-grade matches anywhere PHP is scanned.
- `phishing_kit_realtime` now requires the filename to combine a brand (paypal/microsoft/office365/...) AND a phishing indicator (login/verify/secure/...). Dropped `kit` from the signal set since legitimate plugin slugs end in `-kit` (google-site-kit). Stops FPs on plugin distribution backups under `wpvividbackups/`.
- `email_suspicious_forwarder` realtime watcher establishes a baseline on first observation of a `valiases/<domain>` file and only alerts when the hash changes thereafter -- matches the scheduled audit's behaviour. Stops the alert flood every WHM-rsync account transfer caused. Pipe forwarders (`|/path/to/script`) and `/dev/null` blackholes still alert even on first observation -- they are dangerous regardless of whether the file is freshly arrived.

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
