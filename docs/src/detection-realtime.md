# Real-Time Detection

CSM detects threats in under 2 seconds using kernel and log watchers running inside the daemon: a fanotify file monitor, inotify tailers on auth/access/mail/FTP logs and the Exim spool, and a PAM brute-force listener.

## fanotify File Monitor (< 1 second)

Monitors the mounts containing `/home`, `/tmp`, `/dev/shm`, `/var/tmp`, configured `account_roots`, and detected cPanel document roots.

Atomic-save files enter the same bounded worker queue as ordinary writes.
Where supported, create events inspect available content; close-write events inspect the
completed write. Scans read the original event descriptor even if the file has
been renamed, replaced, or deleted before analysis. No rename event is needed
to inspect those bytes. Repeated findings use the normal alert cooldown, and
queue overflow schedules a directory rescan of files that remain on disk.
Kernel notification loss still relies on the next deep scan. A rename-only
arrival without a usable create or close-write event is also first examined
by the rolling content scan; the watcher does not subscribe to rename events.

For WordPress atomic saves, the intended basename can select a core or plugin
checksum entry. Only a match against the complete event-file content verifies
the file; missing checksums, partial content, and modifications proceed through
normal detection. The finding retains the actual event path.

A WordPress update is unpacked under `wp-content/upgrade/` before it is moved
into place, and each staged PHP file is judged by hash rather than by location.
A file that matches the official wordpress.org checksum for its package version
is stock and skips detection like an installed stock file. A file whose
checksums are still being fetched is content-scanned now and compared once they
land, even if the package header was written late or WordPress has already
moved the tree into place. A file the official package does not ship gets its
own warning, naming the installed path when it still exists. Themes, packages
not published on wordpress.org, a full verification queue, and a package whose
checksums do not arrive within 60 seconds raise one warning per staging
directory. WordPress picks a new staging directory for every upload. Once the
package type and version are known, these warnings are identified by site,
package type, name, version and reason. Uploading the same declared release to
the same site again is a repeat and follows the normal 24-hour reminder. This
groups checksum-availability warnings; it does not establish that the package
contents are unchanged or safe. Incomplete headers keep an upload-specific
warning, and a later change of type, version or reason can raise a new warning
in the same directory. Per-file checksum warnings repeat across uploads only
when their package identity, relative path and complete digest match; files
that could not be hashed keep their upload-specific warning. Content findings
inside staging keep their own per-file identity and normal alert cooldowns;
package-warning dismissal does not dismiss them.

**Detects:**
- Webshell creation (PHP files in web directories)
- Self-deleting droppers: a PHP or executable created under a document root and unlinked within `thresholds.dropper_unlink_ttl_sec` (default 300s), the loader technique that creates a rogue admin then erases itself before any scan. A file whose exact bytes WordPress moved or copied into place before removing the original is not reported: plugin, theme and core packages, language packs, and the version file a core update reads first. Language-pack and version-probe copies also require a complete, stable data-only snapshot with no suspicious content or earlier unsafe write. A core update that stops after reading its version file leaves the old release installed, so no installed copy matches; that version file is not reported when its bytes equal the wordpress.org checksum for the release and locale it declares. Checksum downloads start in the background when capacity permits, and a file still unverified at the deletion probe is reported. Other executable files do not qualify for this copy exception. The script Really Simple Security copies into uploads to test whether PHP runs there, then deletes, is not reported when its content is byte for byte the shipped script; any other content under that name is. A core update unpacks the whole release but installs only what changed and never overwrites the bundled themes and plugins; a staged file it deletes that way is not reported when its bytes equal the wordpress.org checksum for that path in the release now installed. Other files removed from staging without an identical installed copy are still reported. Upgrade staging, atomic-save temp files, template compile caches, a path taken over by a newer file, and a file whose original directory was removed are recognized and reported at a lower severity; a create/delete burst collapses into one lower-severity notice. Off with `thresholds.dropper_detection: false`. Candidate tracking and findings held for aggregation each accept up to 16,384 entries; additional work is refused without evicting older evidence. Status and doctor report refusals, exhausted probes, overdue work and stalled processing through [protection queue health](api.md#protection-queue-health).
- Dropper admission and pending findings follow the live `suppressions.ignore_paths` list after reload. Intentionally suppressed candidates consume no tracker capacity; losses of eligible candidates still raise the capacity warning.
- PHP in uploads, languages, upgrade directories
- PHP in `.ssh`, `.cpanel`, mail directories (critical escalation)
- Executable drops in `.config`
- `.htaccess` injection and tampering (auto_prepend, eval/base64 handlers, CGI execution remaps, and ModSecurity disablement)
- `.user.ini` tampering and `php.ini` tampering under configured or detected web roots
- Obfuscated PHP (encoded, packed, concatenated)
- Fragmented base64 evasion (`$a="base"; $b="64_decode"` -- function name split across variables)
- Concatenation payloads (hundreds of `$z .= "xxxx"` lines with eval at end)
- Tail scanning: payloads appended to the end of large legitimate PHP files (beyond the 32KB head window)
- CGI backdoors: Perl, Python, Bash, Ruby scripts in web directories (e.g., LEVIATHAN toolkit)
- SEO spam: gambling/togel dofollow link injection in PHP/HTML files
- Phishing pages and credential harvest logs
- Phishing kit ZIP archives
- PHP carried inside a file served as an image. Image writes under an account or configured document root are inspected, including hosted `.config` directories and roots located in temporary directories. Images up to 128 KiB are inspected in one piece; larger files get a 64 KiB head and a 64 KiB tail scan. Payloads outside those windows require a deep scan, subject to `thresholds.full_scan_max_file_mb`. A PHP opening tag alone is not enough -- a screenshot quoting one in its description chunk stays quiet -- and a file that only wears an image name while holding PHP source is reported the same way. Finding: `php_in_image_realtime`.
- A PHP file that includes or requires an image, archive or other non-executable file while also reading request input. That pairing is the loader half of the technique above: the payload lives in the picture and the one-line loader elsewhere. Literal targets ending an include statement, concatenated paths, paths held in a local, encoded paths and suppressed `@include` statements match in either statement order. Ordinary templating that pulls in `.html`, `.tpl`, `.txt` or `.svg` partials is outside the extension-based rule. Encoded targets still count because the source hides their extension.
- YAML signature matches (PHP, HTML, .htaccess, .user.ini, php.ini)
- YARA-X rule matches (if built with `-tags yara`)

Completed upload execution probes remain tracked until the deletion check so
combined or out-of-order create and close-write events preserve completion
evidence. A probe without a completed write, or with earlier unsafe or
uncertain content, remains reportable.
Image writes use the existing notification-only fanotify instance, its 16,384
event queue and 4-16 analyzer workers. They create no permission-event holds
and do not enter the mail scanner. Thumbnail and WebP bursts fill the same
queue as other writes: excess events are closed immediately and their parent
directories enter the existing capped recovery tracker. Recovery rescans
recent surviving files; kernel queue loss and exhausted recovery coverage
still rely on the next deep scan. Queue health and content-read truncation
remain visible through the existing metrics. Mail permission holds retain
their separate hold budget and watchdog.

Both the real-time and the scheduled WordPress admin-creation signature
require an administrator role token plus literal or request-derived
credentials, and both accept the same ASCII whitespace, including the vertical
tab. An importer that creates users with a generated password does not trigger
either one just for reading a login from an import form.

Two divergences between the engines are known and left in place. Go folds the
Unicode long s into ASCII s and YARA's nocase does not, so a token spelled
with it can match in real time where a scan declines. Bounded expressions also
count differently: the real-time engine counts characters and the scheduled one
counts bytes. Neither can occur in real PHP, and both belong in the scanner's
regex compilation rather than in hand-written escapes inside every rule.
Strictness parity is not enforced across the rulesets: the parity check
compares rule names, not how strict each side is.

Complete blank files are excluded from dropper alerts after a close-write
observation. Any content or metadata change during the read, including an
unlink, leaves the snapshot uncertain. WordPress data and its checksum are
read within the same stat interval. A later complete close-write snapshot
cannot rule out code that ran during an earlier unstable read. That
uncertainty and code seen in any read remain attached to the tracked file.
Concurrent firewall-log writes can therefore still produce a warning when
the log is replaced, or a critical finding when it is deleted.

Core-release checksum downloads are non-blocking and bounded, including
their retry timers. Repeated misses and streams of distinct release names
share an admission budget. Release identifiers longer than 64 bytes are
rejected before retention or lookup. When that budget is exhausted, cached checksums
remain usable; an uncached file stays unverified and receives the normal
dropper assessment. A later observation can request checksums again after
the budget recovers.

PHP files are also excluded when their first statement stops the interpreter
(`exit`, `die`, or `__halt_compiler`, with at most a plain literal argument and
no preceding comment). Plugins keep state and firewall data in files of that
shape and rewrite them constantly, and the bytes behind the terminator are
never compiled. The exemption is refused when those trailing bytes are made
only of transport-encoding alphabet: an operator who turns on PHP source
conversion can have a file decoded before it is tokenized, which would make an
encoded tail the program and this header padding. Comment-bearing PHP remains
eligible for the same reason -- a comment's tokens depend on the interpreter's
source encoding. Executable-mode files are not judged by PHP compilation rules,
because a shell may read them instead. Content or signature findings and
previously observed code always override inert-content filtering.

**Features:**
- Per-path alert deduplication (30s cooldown)
- Process info enrichment (PID, command, UID)
- Auto-quarantine on high-confidence realtime signature matches (category, size, entropy, and hex/execution validation)

## Sensitive System File Watcher

Tracks a fixed set of system-configuration paths: the account and credential databases, `sudoers` and its drop-in directory, the SSH daemon config and its drop-in directory, the system cron drop-in directories, and per-user crontabs. The set is not operator-configurable -- a path an attacker knows is excluded is a free landing pad.

The backend is chosen by `detection.sensitive_files_backend`. The `bpf` backend attaches an LSM hook that catches writes as they happen, and re-expands the watchset every `detection.sensitive_files_poll_interval` (default 5m). The `legacy` backend content-hashes the watchset on the same interval.

Both backends key on the path, not the inode. Most tools replace a config file by writing a temporary file and renaming it over the target, which gives the path a new inode and hides the write from the LSM hook. The BPF refresh therefore compares content and security metadata per path: a rename-over is reported as a change on the existing file, only a path no previous refresh had seen is reported as newly appeared, and a regular-file rewrite that leaves bytes, permissions, and ownership unchanged is not reported. It also tracks symlink targets, so retargeting a watched path remains visible even when both targets contain the same bytes. Non-regular entries are tracked by path identity without opening them for content reads. The legacy poller compares content digests by path.

Findings are `sensitive_file_modified`. A write finding successfully delivered by the LSM hook wins only while the path still has the exact state captured for that finding. The refresh reports a later rename-over separately, retries a refresh finding if the alert queue was full, and always evaluates the bytes used for its digest rather than a later read. Writes inside a package-manager window, or by a process whose ancestor is a package manager, are demoted to Warning unless a cron payload carries obvious persistence tokens. CSM's own managed writes are suppressed by content, not by path.

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

Successful FTP logins over loopback do not raise an unfamiliar-address warning.
Failed authentication remains reportable over loopback, including through local
relays.

The FTP and SSH log watchers read the same files as the periodic `ftp_logins`
and `ssh_logins` checks, so both see every login. Each login is reported once:
the watcher and the periodic check build the same finding, and the second one
is recognised as a repeat. When the watcher is not running, on a non-cPanel
host or before the log file appears, the periodic check still reports the
login on its own.

The identity uses the complete log record, including its timestamp and session
fields, even when the displayed details are shortened. A later session from the
same address is a new finding within the 24-hour reminder window.

A successful FTP login and a cPanel File Manager write are not emailed. On
shared hosting every customer connects from an address that is not
infrastructure, so both fire on ordinary use of a core feature. They stay on
the findings page, in history, in incident correlation and in the attack
database, where their value is correlation with other evidence on the same
account. Failed FTP authentication, FTP brute force, a login from a
brute-force source, and SSH logins are all still emailed.

The phpanel webhook and SSE event stream still receive these successful
operations; the email and operator-webhook filter runs after data delivery.

#### Login check names on upgrade

New findings use `ftp_login` in place of `ftp_login_realtime`, and
`ssh_login_unknown_ip` in place of `ssh_login_realtime`. Update external
phpanel, export and SIEM rules to accept the merged names. Historical records
and already queued deliveries can still contain the old names; the JSON schema
is unchanged.

Existing `alerts.email.disabled_checks` entries and saved suppression rules for
either retired name also match its replacement. The Settings page displays and
saves the current names. A mute for one former producer now covers the shared
finding from both producers; it does not mute FTP brute-force escalations.

Pending SSH blocks and restored SSH incident evidence retain their blocking
policy. Historical successful FTP activity remains excluded from incident
blocking, including events carrying its retired name.

cPanel-only log watchers are not registered on non-cPanel hosts, so you will not see "not found, retrying every 60s" warnings for them on plain Ubuntu or AlmaLinux.

The Postfix/Dovecot file reader polls every two seconds. It reads replacement
files from the start and rewinds when the current file shrinks below its read
position. Truncation also clears buffered bytes from the previous file contents.
With `copytruncate`, a file that regrows past that position between polls can
hide the truncation and lose events. Use rename/create rotation with the log
writer reopening its file, or journal input, when that loss is unacceptable.

Mail records are emitted only after their newline arrives. A partial record
survives temporary EOF up to the 64 KiB limit, including its newline. Longer
records are discarded through the next newline even when written across
several polls. Rotation and detected truncation clear pending record state.

Mail source attachment retries after failures, starting at one second and
doubling to a maximum delay of 30 seconds. The watcher remains unhealthy and
reports an unavailable-source finding until a reader attaches successfully.
Repeated identical errors are not re-emitted. Retries use the current mail
source configuration and start at the current tail, so delayed attachment does
not count historical authentication failures as new activity.

With `mail_logs.source: auto`, each retry chooses the configured or platform
file if present, otherwise the configured journal units. A file missing for
90 seconds triggers a new selection. The old reader stops before a replacement
starts. Journal input follows new records from the selected services, including
services with no prior entries; it does not replay older records on attachment.

Explicit `file` and `journal` modes retry their selected source without
switching, and a working reader stays attached until it stops or loses its file.
Journal input requires a build with journal support.

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

Five attack patterns:

| Signal | What triggers it | Auto-response |
|--------|-----------------|---------------|
| `mail_bruteforce` | A single attacker IP exceeds the per-IP failed-auth threshold within the configured window without matching successful mailbox activity | IP blocked via nftables |
| `mail_bruteforce_suspected` | An established good source hits the per-IP failed-auth threshold with a confined stale-password pattern | Visibility finding only. No auto-block |
| `mail_subnet_spray` | Multiple distinct attacker IPs from the same /24 subnet exceed the subnet threshold | Entire /24 subnet blocked via nftables |
| `mail_account_spray` | Many distinct attacker IPs targeting the same mailbox exceed the account threshold | Visibility finding only. No auto-block, because attackers span many subnets and no single-IP action helps |
| `mail_account_compromised` | A successful login comes from an IP that repeatedly failed auth against the same mailbox | Critical findings block immediately. A source with established history on at least two other mailboxes emits a High advisory and is not auto-blocked |

Tunable via the `thresholds.mail_bruteforce_*` keys in `csm.yaml`. Independent from the SMTP tracker so the Dovecot noise floor can be tuned separately. Infrastructure IPs are never counted or blocked. Established good sources with a confined stale-password pattern emit `mail_bruteforce_suspected` instead of an IP block, while wider spraying and compromise from a source without established multi-mailbox history still block. A compromise from an IP with established history on at least two other mailboxes remains visible as a High advisory but does not feed direct, incident, or spray auto-blocking. The `mail_bruteforce` and `mail_bruteforce_suspected` alerts name the mailboxes the source was hitting, with per-mailbox failure counts and a count of attempts that named no mailbox, so a real attack on a live mailbox is easy to tell apart from dictionary noise.

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

The detector runs four paths and only fires `email_php_relay_abuse` (Critical) when one of them crosses threshold. Paths 1 and 2 are scoped per-script, using the `host:/path` from the `X-PHP-Script` Exim header. Path 2b is per cPanel user. Path 4 is per HTTP source IP across distinct scripts. Paths 2 and 4 use a recipient-diversity gate that suppresses only known low-recipient notification mail.

| Path | What triggers it | Why it exists |
|------|------------------|---------------|
| **Path 1: header score** | Per-script: `From` domain not in the account's authorised domains AND additional signal (PHPMailer / suspicious Reply-To / suspicious User-Agent), evaluated over a rolling 5-min window once the script has emitted at least `header_score_volume_min` messages | The shape that matched the original incident: spoofed sender, contact-form-style. `FromMismatch` is a HARD precondition -- the score never accumulates without it |
| **Path 2: absolute volume per script** | A single script emits at least `absolute_volume_per_hour` messages in the last hour. If Exim envelope recipients are known, fewer than `fanout_distinct_recipients` distinct recipients suppresses this path; unknown recipients or `fanout_distinct_recipients: 0` fail open. | Catches a compromised script even if the headers themselves are legit-shaped, while leaving plugin notification mail to a fixed admin set alone |
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
  start timestamp. CSM does not infer it from procfs directory metadata.
- After daemon restart, the `csm_process_context_enrich_*` counters may show a
  small `enqueued - reads` delta. Pending requests in the enricher queue are
  dropped on shutdown by design.
- Hosts without BPF support fall back to `/proc/net/tcp[6]` polling. That path
  has no PID, so emitted findings do not carry a `process` field.

## HTTP Flood, Scanner Profile, UA Spoof, and Distributed Flood

`http_request_flood`, `http_scanner_profile`, `http_claimed_bot_unverified`, `http_ua_spoof`, and `http_distributed_flood` are **periodic**, not real-time. They run inside the same `wp_bruteforce` scheduled check that scans per-vhost access logs every 10 minutes. A real-time inotify tailer would need to hold per-IP state across log rotations and is out of scope for the initial release (see the plan non-goals). For attack types where sub-minute response matters, the access-log inotify watcher already covers wp_login_bruteforce and xmlrpc_abuse; the periodic scan adds volume-based rate enforcement, pending claimed-bot handling, scanner-profile detection, and per-vhost distributed attack rollups on top.

A verified crawler is dropped from the scan before any counter increments: a source IP whose claimed bot User-Agent passes IP-range or reverse-DNS verification cannot contribute to a flood, scanner, or spoof finding, so verified Googlebot and AI crawler traffic does not produce false positives. Verification is covered in [Threat intel](threat-intel.md#verified-crawlers).

| Finding | Fires when | Key gates (defaults) |
|---------|------------|----------------------|
| `http_request_flood` | One source IP makes too many requests inside the rate window | `http_flood_threshold` requests within `http_flood_window_min` (5 min). Ships disabled (`0`) so operators sample baseline traffic first |
| `http_scanner_profile` | One source IP's in-window traffic is almost all probe-error responses spread across many distinct paths, the shape of URL enumeration hunting for backups, downloadable files, and dormant shells | Three gates must all pass: `http_scanner_min_requests` volume (ships `0`, disabled), at least `http_scanner_error_pct` (90) of requests on a probe-error status, and `http_scanner_min_distinct_paths` (10) distinct error paths. Probe-error statuses default to 404 and 403; query strings are stripped so cache-buster URLs on one missing endpoint count once |
| `http_ua_spoof` | One source IP sends non-browser User-Agents | Known scanner agents (nikto, sqlmap, nmap, wpscan, nuclei, and similar) fire on the first hit. Claimed crawler UAs with a cache-confirmed reverse-DNS negative, scripting (curl/python/wget), headless (Puppeteer/Playwright), and empty agents fire at `http_ua_spoof_threshold` (30); scripting/headless/empty still require their opt-in flags (`http_ua_scripting_enabled`, `http_ua_headless_enabled`, `http_ua_empty_enabled`) |
| `http_distributed_flood` | Many distinct already-abusive source IPs hit one vhost in a single scan window | Opt-in: fires once `http_distributed_min_ips` distinct IPs (sample 10), each having already crossed a per-IP abuse threshold above, hit the same vhost. Built only from IPs that tripped another finding, so a popular site's normal visitor spread does not trip it |

Per-IP findings roll up per vhost, so a confirmed scanner that sprays a few probes across many vhosts still feeds the distributed rollup. Full threshold reference and tuning notes are in [Configuration](configuration.md).

## Direct SMTP Egress

Outbound connections to SMTP ports from non-MTA local processes
emit a `direct_smtp_egress` finding. See
[Direct SMTP egress](direct-smtp-egress.md) for the full rule set,
config schema, and metric.
