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
| Exim mainlog (`/var/log/exim_mainlog`) | cPanel only | Mail anomalies, queue issues |
| Apache/LiteSpeed/Nginx access log | All | WordPress brute force (wp-login.php, xmlrpc.php), real-time. Paths: `/var/log/apache2/access.log` (Debian), `/var/log/httpd/access_log` (RHEL), `/var/log/nginx/access.log` (Nginx), `/usr/local/apache/logs/access_log` (cPanel) |
| Dovecot log (`/var/log/maillog`) | cPanel only | IMAP/POP3 account compromise |
| FTP log (`/var/log/messages`) | cPanel only | FTP logins and failures |
| ModSecurity error log | All (if ModSec installed) | WAF blocks and attacks. Auto-discovered from the detected web server |
| Nginx error log (`/var/log/nginx/error.log`) | Nginx hosts | General web errors, ModSecurity denies |

Cpanel-only log watchers are not registered on non-cPanel hosts, so you will not see "not found, retrying every 60s" warnings for them on plain Ubuntu or AlmaLinux.

## SMTP / Dovecot Brute-Force Tracker

Detects credential stuffing and password spray against mail authentication. Runs as part of the Exim mainlog watcher on cPanel hosts.

Three attack patterns:

| Signal | What triggers it | Auto-response |
|--------|-----------------|---------------|
| `smtp_bruteforce` | A single attacker IP exceeds the per-IP failed-auth threshold within the configured window | IP blocked via nftables |
| `smtp_subnet_spray` | Multiple distinct attacker IPs from the same /24 subnet exceed the subnet threshold | Entire /24 subnet blocked via nftables |
| `smtp_account_spray` | Many distinct attacker IPs targeting the same mailbox exceed the account threshold | Visibility finding only. No auto-block, because attackers span many subnets and no single-IP action helps |

Tunable via the `thresholds.smtp_bruteforce_*` keys in `csm.yaml`. Infrastructure IPs (from `infra_ips`) are never counted or blocked.

## Mail Auth Brute-Force Tracker

Detects credential stuffing and password spray against IMAP, POP3, and ManageSieve. Runs as part of the Dovecot log watcher on cPanel hosts. The wrapper composes with the existing geo-based login monitor, so `email_suspicious_geo` keeps firing for successful logins from novel countries.

Four attack patterns:

| Signal | What triggers it | Auto-response |
|--------|-----------------|---------------|
| `mail_bruteforce` | A single attacker IP exceeds the per-IP failed-auth threshold within the configured window | IP blocked via nftables |
| `mail_subnet_spray` | Multiple distinct attacker IPs from the same /24 subnet exceed the subnet threshold | Entire /24 subnet blocked via nftables |
| `mail_account_spray` | Many distinct attacker IPs targeting the same mailbox exceed the account threshold | Visibility finding only. No auto-block, because attackers span many subnets and no single-IP action helps |
| `mail_account_compromised` | A successful login comes from an IP that just failed auth against the same account | IP blocked immediately. Rotate the password and revoke sessions |

Tunable via the `thresholds.mail_bruteforce_*` keys in `csm.yaml`. Independent from the SMTP tracker so the Dovecot noise floor can be tuned separately. Infrastructure IPs are never counted or blocked.

## Admin-Panel Brute-Force Tracker

Counts repeated POST requests to high-value non-WordPress admin login endpoints. Runs as part of the web access-log watcher.

Covered endpoints (tight set to avoid false positives on shared hosting):

- phpMyAdmin: `/phpmyadmin/index.php`, `/pma/index.php`, `/phpMyAdmin/index.php`
- Joomla: `/administrator/index.php`

When an IP crosses the POST-rate threshold, `admin_panel_bruteforce` fires and the attacker IP is auto-blocked.

Drupal `/user/login` and Tomcat Manager `/manager/html` are intentionally out of scope here. Drupal's path is too generic on shared hosting, and Tomcat Manager uses HTTP Basic auth (repeated GET requests with 401 responses), not POST form submissions. Both need different detectors and are tracked as follow-up work.

## PHP-Relay (Mail Abuse, cPanel Only)

Real-time inotify watcher on `/var/spool/exim/input` catches WordPress contact-form spam relays where an attacker uses PHPMailer (or similar) with a spoofed `From`, an external `Reply-To`, and a script URL that doesn't belong to the cPanel account. The `occonsultingcy` incident (2026-04) drove the design: a legitimate site running a vulnerable contact-form plugin became a per-message spam relay through the operator's own mail account.

The detector runs four paths and only fires `email_php_relay_abuse` (Critical) when one of them crosses threshold. All four are scoped per-script — the `host:/path` from the `X-PHP-Script` Exim header — so a single noisy plugin doesn't tar the whole account.

| Path | What triggers it | Why it exists |
|------|------------------|---------------|
| **Path 1: header score** | Per-script: `From` domain not in the account's authorised domains AND additional signal (PHPMailer / suspicious Reply-To / suspicious User-Agent), evaluated over a rolling 5-min window once the script has emitted at least `header_score_volume_min` messages | The shape that matched the original incident: spoofed sender, contact-form-style. `FromMismatch` is a HARD precondition — the score never accumulates without it |
| **Path 2: absolute volume per script** | A single script emits more than `absolute_volume_per_hour` messages in the last hour | Catches a compromised script even if the headers themselves are legit-shaped |
| **Path 2b: account log-tail volume** | Per cPanel user: more than `effective_account_limit` outbound messages through the redirect_resolver router in the last hour. The effective limit is auto-derived from `/var/cpanel/cpanel.config`'s `maxemailsperhour` (60% of it, clamped to 20-60), capped at 95% of the cPanel limit when an operator override is set | Backstop for when Path 2 misses the window. Reads `/var/log/exim_mainlog` directly; only fires on lines tagged `B=redirect_resolver` so forwarders don't trip it |
| **Path 4: HTTP-IP fanout** | Per-script: more than `fanout_distinct_scripts` distinct attacker IPs hitting the same script in `fanout_window_min` minutes, after subtracting any IP that matches the loaded HTTP-proxy ranges (Cloudflare etc.) | Distinguishes one bad script behind a CDN (legit traffic, even if buggy) from a coordinated attack across many real source IPs |

Path 5 (behavioural baseline) is deferred to Stage 2.

The detector starts a one-shot retrospective scan of `exim_mainlog` at daemon startup so Path 2b can fire on history already on disk. `IN_Q_OVERFLOW` triggers a bounded recovery walk of the spool (capped at 1000 files; if more were skipped, a `email_php_relay_overflow_scan_truncated` Critical fires too — Path 2b backstops the missed messages).

Operator suppressions (`csm phprelay ignore-script <host:/path>`) short-circuit the pipeline before any path scoring runs, so a known-noisy contact form can be opted out individually without disabling the detector. See [PHP-relay CLI](cli.md#php-relay-mail-abuse-cpanel-only) for the full operator surface.

## PAM Brute-Force Listener

Real-time authentication monitoring across all PAM-enabled services.

- SSH login tracking with geolocation
- cPanel, FTP, and webmail authentication
- Blocks IPs within seconds of threshold breach
- Integrates with the nftables firewall for instant blocking
