# Critical Checks

34 checks, run every 10 minutes. Complete in under 1 second.

## Process & System

| Check | Description |
|-------|-------------|
| `fake_kernel_threads` | Non-root processes masquerading as kernel threads (rootkit indicator) |
| `suspicious_processes` | Reverse shells, interactive shells, GSocket, suspicious executables |
| `php_processes` | PHP process execution, working dirs, environment variables |
| `shadow_changes` | /etc/shadow modification outside maintenance windows |
| `uid0_accounts` | Unauthorized root (UID 0) accounts |
| `kernel_modules` | Kernel module loading (post-baseline) |

## SSH & Access

| Check | Description |
|-------|-------------|
| `ssh_keys` | Unauthorized entries in /root/.ssh/authorized_keys |
| `sshd_config` | SSH hardening (PermitRootLogin, PasswordAuthentication, etc.) |
| `ssh_logins` | SSH access anomalies with geolocation |
| `api_tokens` | cPanel/WHM API token usage |
| `whm_access` | WHM/root login patterns, multi-IP access |
| `cpanel_logins` | cPanel login anomalies, multi-IP correlation |
| `cpanel_filemanager` | File Manager usage for unauthorized access |

## Network

| Check | Description |
|-------|-------------|
| `outbound_connections` | Root-level outbound to non-infra IPs (C2, backdoor ports) |
| `user_outbound` | Per-user outbound connections (non-standard ports) |
| `dns_connections` | DNS exfiltration and suspicious queries |
| `firewall` | Firewall status and rule integrity |

## Brute Force & Auth

| Check | Description |
|-------|-------------|
| `wp_bruteforce` | WordPress login brute force (wp-login.php, xmlrpc.php) |
| `ftp_logins` | FTP access patterns and failed auth |
| `webmail_logins` | Roundcube/Horde access anomalies |
| `api_auth_failures` | API authentication failure patterns |

## Email

| Check | Description |
|-------|-------------|
| `mail_queue` | Mail queue buildup (spam outbreak indicator) |
| `mail_per_account` | Per-account email volume spikes |

## Data & Integrity

| Check | Description |
|-------|-------------|
| `crontabs` | Suspicious cron jobs and scheduled commands |
| `mysql_users` | MySQL user accounts and privileges |
| `database_dumps` | Database exfiltration attempts |
| `exfiltration_paste` | Connections to pastebin/code-sharing sites |

## Threat Intelligence

| Check | Description |
|-------|-------------|
| `ip_reputation` | IPs against external threat databases (AbuseIPDB) |
| `local_threat_score` | Aggregated score from internal attack database |
| `modsec_audit` | ModSecurity audit log parsing |

## Performance

| Check | Description |
|-------|-------------|
| `perf_load` | CPU load average thresholds |
| `perf_php_processes` | PHP process count and memory |
| `perf_memory` | Swap usage and OOM killer activity |

## Health

| Check | Description |
|-------|-------------|
| `health` | Daemon health, binary integrity, required services |

## Platform Support

Runs on every supported platform unless noted below. The daemon auto-detects OS and panel at startup and silently skips cPanel-specific checks on plain Linux hosts (no "not found" spam).

**cPanel-only** (skipped on plain Ubuntu/AlmaLinux):

- `api_tokens`, `whm_access`, `cpanel_logins`, `cpanel_filemanager` -- read WHM API and cPanel session logs
- `wp_bruteforce` -- iterates `/home/*/public_html/*/wp-login.php` and per-domain access logs
- `webmail_logins` -- parses cPanel Roundcube/Horde logs
- `mail_queue`, `mail_per_account` -- read Exim queue and `/var/log/exim_mainlog`

**Plain Linux equivalents** that still provide coverage:

- Access log brute-force detection (`wp_login_bruteforce`, `xmlrpc_abuse`) runs against the detected web server's access log (`/var/log/nginx/access.log` or `/var/log/httpd/access_log`), so WordPress brute-force alerts still fire on non-cPanel hosts -- they just rely on the live log watcher rather than per-domain domlog scanning.
- `modsec_audit` runs on any host with ModSecurity installed.
- `ssh_logins`, SSH brute force, PAM listener, firewall, kernel modules, RPM/DEB integrity, and threat intelligence all run on every supported platform.
