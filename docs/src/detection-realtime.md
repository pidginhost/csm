# Real-Time Detection

CSM detects threats in under 2 seconds using three kernel-level watchers running inside the daemon.

## fanotify File Monitor (< 1 second)

Monitors `/home`, `/tmp`, `/dev/shm` for filesystem events.

**Detects:**
- Webshell creation (PHP files in web directories)
- PHP in uploads, languages, upgrade directories
- PHP in `.ssh`, `.cpanel`, mail directories (critical escalation)
- Executable drops in `.config`
- `.htaccess` injection (auto_prepend, eval, base64 handlers)
- `.user.ini` tampering
- Obfuscated PHP (encoded, packed, concatenated)
- Fragmented base64 evasion (`$a="base"; $b="64_decode"` -- function name split across variables)
- Concatenation payloads (hundreds of `$z .= "xxxx"` lines with eval at end)
- Tail scanning: payloads appended to the end of large legitimate PHP files (beyond the 32KB head window)
- CGI backdoors: Perl, Python, Bash, Ruby scripts in web directories (e.g., LEVIATHAN toolkit)
- SEO spam: gambling/togel dofollow link injection in PHP/HTML files
- Phishing pages and credential harvest logs
- Phishing kit ZIP archives
- YAML signature matches (PHP, HTML, .htaccess, .user.ini)
- YARA-X rule matches (if built with `-tags yara`)

**Features:**
- Per-path alert deduplication (30s cooldown)
- Process info enrichment (PID, command, UID)
- Auto-quarantine on high-confidence matches (category + entropy validation)

## inotify Log Watchers (~2 seconds)

Tails auth, access, and mail logs in real-time. The exact file paths are chosen per platform at daemon startup -- see the `platform: ...` line in the daemon log.

| Log | Platforms | What it detects |
|-----|-----------|-----------------|
| cPanel session log (`/usr/local/cpanel/logs/session_log`) | cPanel only | Logins from non-infra IPs, password changes, File Manager uploads |
| cPanel access log (`/usr/local/cpanel/logs/access_log`) | cPanel only | cPanel-API auth patterns |
| Auth log | All | SSH logins and failures. `/var/log/auth.log` on Debian/Ubuntu, `/var/log/secure` on RHEL family and cPanel |
| Exim mainlog (`/var/log/exim_mainlog`) | cPanel; non-cPanel when the file exists | Mail anomalies, queue issues, SMTP brute force, probe abuse, and cloud relay abuse |
| Apache/LiteSpeed/Nginx access log | All | WordPress brute force (wp-login.php, xmlrpc.php), real-time. Paths: `/var/log/apache2/access.log` (Debian), `/var/log/httpd/access_log` (RHEL), `/var/log/nginx/access.log` (Nginx), `/usr/local/apache/logs/access_log` (cPanel) |
| Mail log (platform file or journal) | All hosts with Postfix/Dovecot logs | IMAP/POP3/ManageSieve account compromise and mail brute-force |
| FTP log (`/var/log/messages`) | cPanel only | FTP logins and failures |
| ModSecurity error log | All (if ModSec installed) | WAF blocks and attacks. Auto-discovered from the detected web server |
| Nginx error log (`/var/log/nginx/error.log`) | Nginx hosts | General web errors, ModSecurity denies |

cPanel-only log watchers are not registered on non-cPanel hosts, so you will not see "not found, retrying every 60s" warnings for them on plain Ubuntu or AlmaLinux.

## SMTP / Dovecot Brute-Force Tracker

Detects credential stuffing, password spray, and raw SMTP probe storms. Runs as part of the Exim mainlog watcher on cPanel hosts and on non-cPanel Exim hosts where `/var/log/exim_mainlog` exists.

Four attack patterns:

| Signal | What triggers it | Auto-response |
|--------|-----------------|---------------|
| `smtp_bruteforce` | A single attacker IP exceeds the per-IP failed-auth threshold within the configured window | IP blocked via nftables |
| `smtp_probe_abuse` | A single attacker IP exceeds the raw SMTP connect-rate threshold before AUTH | IP blocked via nftables |
| `smtp_subnet_spray` | Multiple distinct attacker IPs from the same /24 subnet exceed the subnet threshold | Entire /24 subnet blocked via nftables |
| `smtp_account_spray` | Many distinct attacker IPs targeting the same mailbox exceed the account threshold | Visibility finding only. No auto-block, because attackers span many subnets and no single-IP action helps |

Tunable via the `thresholds.smtp_bruteforce_*` and `thresholds.smtp_probe_*` keys in `csm.yaml`. Infrastructure IPs (from `infra_ips`) are never counted or blocked.

## Cloud-Relay Credential Abuse

Detects authenticated outbound Exim deliveries where the same mailbox is sending through public-cloud relay sources. The realtime Exim mainlog watcher evaluates new accepted deliveries, and a bounded startup replay covers recent lines already on disk.

The finding is `email_cloud_relay_abuse`. Auto-response actions follow the global dry-run and block settings plus the email hold path. Operators with legitimate cloud mailers can opt out specific mailboxes or domains under `email_protection.cloud_relay`, or use `email_protection.high_volume_senders` for known high-volume senders.

## Mail Auth Brute-Force Tracker

Detects credential stuffing and password spray against IMAP, POP3, and ManageSieve. Runs through the `mail_logs` reader: file source uses `/var/log/mail.log` on Debian-family hosts and `/var/log/maillog` on RHEL-family and cPanel hosts, while journal source reads configured Postfix/Dovecot units. The wrapper composes with the existing geo-based login monitor, so `email_suspicious_geo` keeps firing for successful logins from novel countries.

Four attack patterns:

| Signal | What triggers it | Auto-response |
|--------|-----------------|---------------|
| `mail_bruteforce` | A single attacker IP exceeds the per-IP failed-auth threshold within the configured window without matching successful mailbox activity | IP blocked via nftables |
| `mail_subnet_spray` | Multiple distinct attacker IPs from the same /24 subnet exceed the subnet threshold | Entire /24 subnet blocked via nftables |
| `mail_account_spray` | Many distinct attacker IPs targeting the same mailbox exceed the account threshold | Visibility finding only. No auto-block, because attackers span many subnets and no single-IP action helps |
| `mail_account_compromised` | A successful login comes from an IP that repeatedly failed auth against the same mailbox | IP blocked immediately. Rotate the password and revoke sessions |

Tunable via the `thresholds.mail_bruteforce_*` keys in `csm.yaml`. Independent from the SMTP tracker so the Dovecot noise floor can be tuned separately. Infrastructure IPs are never counted or blocked. Recent successful logins for the same mailbox can suppress single-IP mail auth blocks, which avoids blocking a shared office address when one client has a stale saved password.

When the mail authentication backend itself fails (for example dovecot cannot reach `cpdoveauthd`), every login fails regardless of password. CSM detects a burst of these backend errors, pauses `mail_bruteforce` and `mail_subnet_spray` auto-blocking, and raises a `mail_auth_backend_degraded` warning so the outage is visible instead of mass-blocking legitimate users. Detection resumes automatically once the backend recovers.

## Admin-Panel Brute-Force Tracker

Counts repeated POST requests to high-value non-WordPress admin login endpoints. Runs as part of the web access-log watcher.

Covered endpoints (tight set to avoid false positives on shared hosting):

- phpMyAdmin: `/phpmyadmin/index.php`, `/pma/index.php`, `/phpMyAdmin/index.php`
- Joomla: `/administrator/index.php`

When an IP crosses the POST-rate threshold, `admin_panel_bruteforce` fires and the attacker IP is auto-blocked.

Drupal `/user/login` and Tomcat Manager `/manager/html` are intentionally out of scope here. Drupal's path is too generic on shared hosting, and Tomcat Manager uses HTTP Basic auth (repeated GET requests with 401 responses), not POST form submissions. Both need different detectors and are tracked as follow-up work.

## PHP-Relay (Mail Abuse, cPanel Only)

Real-time inotify watcher on `/var/spool/exim/input` catches WordPress contact-form spam relays where an attacker uses PHPMailer (or similar) with a spoofed `From`, an external `Reply-To`, and a script URL that doesn't belong to the cPanel account. The `occonsultingcy` incident (2026-04) drove the design: a legitimate site running a vulnerable contact-form plugin became a per-message spam relay through the operator's own mail account.

The detector runs four paths and only fires `email_php_relay_abuse` (Critical) when one of them crosses threshold. Paths 1 and 2 are scoped per-script, using the `host:/path` from the `X-PHP-Script` Exim header. Path 2b is per cPanel user. Path 4 is per HTTP source IP across distinct scripts, with a recipient-diversity gate that suppresses only known low-recipient notification fanout.

| Path | What triggers it | Why it exists |
|------|------------------|---------------|
| **Path 1: header score** | Per-script: `From` domain not in the account's authorised domains AND additional signal (PHPMailer / suspicious Reply-To / suspicious User-Agent), evaluated over a rolling 5-min window once the script has emitted at least `header_score_volume_min` messages | The shape that matched the original incident: spoofed sender, contact-form-style. `FromMismatch` is a HARD precondition -- the score never accumulates without it |
| **Path 2: absolute volume per script** | A single script emits more than `absolute_volume_per_hour` messages in the last hour | Catches a compromised script even if the headers themselves are legit-shaped |
| **Path 2b: account log-tail volume** | Per cPanel user: more than `effective_account_limit` outbound messages through the redirect_resolver router in the last hour. The effective limit is auto-derived from `/var/cpanel/cpanel.config`'s `maxemailsperhour` (60% of it, clamped to 20-60), capped at 95% of the cPanel limit when an operator override is set | Backstop for when Path 2 misses the window. Reads `/var/log/exim_mainlog` directly; only fires on lines tagged `B=redirect_resolver` so forwarders don't trip it |
| **Path 4: HTTP-IP fanout** | Per HTTP source IP: one source IP appears in at least `fanout_distinct_scripts` distinct script keys in `fanout_window_min` minutes, after excluding loaded HTTP-proxy ranges, loopback, and the host's own interface addresses. If Exim envelope recipients are known, fewer than `fanout_distinct_recipients` distinct recipients suppresses this path; unknown recipients or `fanout_distinct_recipients: 0` fail open. | Catches one client walking many scripts while avoiding CDN/proxy traffic, local cron or panel callbacks, and fixed-admin notification fanout |

Path 5 (behavioural baseline) is deferred to Stage 2.

The detector starts a one-shot retrospective scan of `exim_mainlog` at daemon startup so Path 2b can fire on history already on disk. `IN_Q_OVERFLOW` triggers a bounded recovery walk of the spool (capped at 1000 files; if more were skipped, a `email_php_relay_overflow_scan_truncated` Critical fires too -- Path 2b backstops the missed messages).

Operator suppressions (`csm phprelay ignore-script <host:/path>`) short-circuit the pipeline before any path scoring runs, so a known-noisy contact form can be opted out individually without disabling the detector. See [PHP-relay CLI](cli.md#php-relay-mail-abuse-cpanel-only) for the full operator surface.

## PAM Brute-Force Listener

Real-time authentication monitoring across all PAM-enabled services.

- SSH login tracking with geolocation
- cPanel, FTP, and webmail authentication
- Credential stuffing / password spray breadth: one source IP failing against many distinct accounts inside `thresholds.multi_ip_login_window_min`. The finding is `credential_stuffing`; tune the account floor with `thresholds.cred_stuffing_distinct_accounts` (default 5).
- Blocks IPs within seconds of threshold breach
- Integrates with the nftables firewall for instant blocking

## Process Context

Exec and outbound-connection findings carry an optional `process` object with
PID, PPID, UID, user, cPanel account (when known), comm, exe, sanitized cmdline,
and a parent chain up to depth 5. The chain is materialized from an in-memory
LRU+TTL cache (cap 16384 entries, 30-minute TTL) populated from BPF exec
events. Cache misses trigger a bounded async `/proc` read, so process-context
enrichment does not add blocking work to the connection event loop. When
neither cache nor enricher has data (e.g., a process that exited before
userspace reads its event), the `process` field is omitted entirely and the
finding still emits.

Counters exposed at `/metrics`:

- `csm_process_context_cache_entries`
- `csm_process_context_cache_evictions_total` (LRU)
- `csm_process_context_cache_ttl_purges_total`
- `csm_process_context_cache_misses_total` (includes TTL purges)
- `csm_process_context_enrich_queue_drops_total`
- `csm_process_context_enrich_reads_total`
- `csm_process_context_enrich_errors_total`
- `csm_process_context_enrich_stale_total`
- `csm_process_context_enrich_latency_seconds`

Caveats:

- `started_at` is emitted only when the event source supplies a trustworthy
  start timestamp. Phase 1 does not infer process start time from procfs
  directory metadata. A future refinement may add `/proc/<pid>/stat` field 22
  + `/proc/stat` btime for kernel-tick precision.
- After daemon restart, the `csm_process_context_enrich_*` counters may show a
  small `enqueued - reads` delta. Pending requests in the enricher queue are
  dropped on shutdown by design.
- Hosts without BPF support fall back to `/proc/net/tcp[6]` polling. That path
  has no PID, so emitted findings do not carry a `process` field. A future
  refinement could resolve the socket inode to a PID via `/proc/<pid>/fd`,
  but that is out of scope for Phase 1.

## HTTP Flood, Scanner Profile, UA Spoof, and Distributed Flood

`http_request_flood`, `http_scanner_profile`, `http_claimed_bot_unverified`, `http_ua_spoof`, and `http_distributed_flood` are **periodic**, not real-time. They run inside the same `wp_bruteforce` scheduled check that scans per-vhost access logs every 10 minutes. A real-time inotify tailer would need to hold per-IP state across log rotations and is out of scope for the initial release (see the plan non-goals). For attack types where sub-minute response matters, the access-log inotify watcher already covers wp_login_bruteforce and xmlrpc_abuse; the periodic scan adds volume-based rate enforcement, pending claimed-bot handling, scanner-profile detection, and per-vhost distributed attack rollups on top.

A verified crawler is dropped from the scan before any counter increments: a source IP whose claimed bot User-Agent passes IP-range or reverse-DNS verification cannot contribute to a flood, scanner, or spoof finding, so verified Googlebot and AI crawler traffic does not produce false positives. Verification is covered in [Threat intel](threat-intel.md#verified-crawlers).

| Finding | Fires when | Key gates (defaults) |
|---------|------------|----------------------|
| `http_request_flood` | One source IP makes too many requests inside the rate window | `http_flood_threshold` requests within `http_flood_window_min` (5 min). Ships disabled (`0`) so operators sample baseline traffic first |
| `http_scanner_profile` | One source IP's in-window traffic is almost all probe-error responses spread across many distinct paths, the shape of URL enumeration hunting for backups, downloadable files, and dormant shells | Three gates must all pass: `http_scanner_min_requests` volume (ships `0`, disabled), at least `http_scanner_error_pct` (90) of requests on a probe-error status, and `http_scanner_min_distinct_paths` (10) distinct error paths. Probe-error statuses default to 404 and 403; query strings are stripped so cache-buster URLs on one missing endpoint count once |
| `http_ua_spoof` | One source IP sends non-browser User-Agents | Known scanner agents (nikto, sqlmap, nmap, wpscan, nuclei, and similar) and claimed crawler UAs with a cache-confirmed reverse-DNS negative fire on the first hit. Scripting (curl/python/wget), headless (Puppeteer/Playwright), and empty agents fire at `http_ua_spoof_threshold` (30) and only when their opt-in flag is set (`http_ua_scripting_enabled`, `http_ua_headless_enabled`, `http_ua_empty_enabled`) |
| `http_distributed_flood` | Many distinct already-abusive source IPs hit one vhost in a single scan window | Opt-in: fires once `http_distributed_min_ips` distinct IPs (sample 10), each having already crossed a per-IP abuse threshold above, hit the same vhost. Built only from IPs that tripped another finding, so a popular site's normal visitor spread does not trip it |

Per-IP findings roll up per vhost, so a confirmed scanner that sprays a few probes across many vhosts still feeds the distributed rollup. Full threshold reference and tuning notes are in [Configuration](configuration.md).

## Direct SMTP Egress

Outbound connections to SMTP ports from non-MTA local processes
emit a `direct_smtp_egress` finding. See
[Direct SMTP egress](direct-smtp-egress.md) for the full rule set,
config schema, and metric.
