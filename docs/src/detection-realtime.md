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

Tails auth, access, and mail logs in real-time.

| Log | What it detects |
|-----|-----------------|
| cPanel session log | Logins from non-infra IPs (with trusted country filtering) |
| cPanel session log | Password changes |
| cPanel session log | File Manager uploads |
| auth/secure log | SSH logins and failures |
| FTP log | FTP logins and failures |
| Exim mainlog | Mail anomalies, queue issues |
| Apache/LiteSpeed access log | WordPress brute force (wp-login.php, xmlrpc.php) — real-time, not just periodic |
| Dovecot log | IMAP/POP3 account compromise |
| Roundcube log | Webmail access anomalies |
| ModSecurity audit log | WAF blocks and attacks |

## PAM Brute-Force Listener

Real-time authentication monitoring across all PAM-enabled services.

- SSH login tracking with geolocation
- cPanel, FTP, and webmail authentication
- Blocks IPs within seconds of threshold breach
- Integrates with the nftables firewall for instant blocking
