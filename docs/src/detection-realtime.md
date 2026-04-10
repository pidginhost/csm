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
- Fragmented base64 evasion (`$a="base"; $b="64_decode"` — function name split across variables)
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

Tails auth, access, and mail logs in real-time. The exact file paths are chosen per platform at daemon startup — see the `platform: ...` line in the daemon log.

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

## PAM Brute-Force Listener

Real-time authentication monitoring across all PAM-enabled services.

- SSH login tracking with geolocation
- cPanel, FTP, and webmail authentication
- Blocks IPs within seconds of threshold breach
- Integrates with the nftables firewall for instant blocking
