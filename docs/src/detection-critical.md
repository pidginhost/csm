# Critical Checks

Critical checks run every 10 minutes. Typical wall-clock cost on a busy shared host is a few seconds; the runner enforces the 10-minute cadence even when a tick takes longer.

## Process & System

| Check | Description |
|-------|-------------|
| `fake_kernel_threads` | Non-root processes masquerading as kernel threads (rootkit indicator) |
| `suspicious_processes` | Reverse shells, interactive shells, GSocket, suspicious executables |
| `php_processes` | PHP process execution, working dirs, environment variables |
| `shadow_changes` | /etc/shadow modification outside maintenance windows |
| `uid0_accounts` | Unauthorized root (UID 0) accounts |
| `kernel_modules` | Kernel module loading (post-baseline) |
| `af_alg_socket_use` | AF_ALG socket use that may indicate Copy Fail exploit activity |
| `af_alg_enforcement` | AF_ALG hardening policy drift and correction status |

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
| `bad_asn_outbound` | Outbound connection whose destination resolves (via GeoLite2-ASN) to a bad or unexpected autonomous system. Config `detection.bad_asn_outbound`: `blocked_asns` (always bad) and/or `allowed_asns` (allowlist mode -- anything outside is bad). Classified for every process including root (the periodic connection scan); non-root connections are also flagged in real time by the live BPF tracker. Off by default; the third leg of the `host_takeover` incident chain |
| `dns_connections` | DNS exfiltration and suspicious queries |
| `firewall` | Firewall status and rule integrity |

## Brute Force & Auth

| Check | Description |
|-------|-------------|
| `wp_bruteforce` | WordPress login brute force (wp-login.php, xmlrpc.php) |
| `http_ua_spoof` | IP claiming a search-engine bot UA (Googlebot, Bingbot, Applebot) that fails reverse-DNS verification, or exceeding the per-IP spoof threshold for scripting/headless/empty UAs when those opt-in flags are enabled |
| `http_distributed_flood` | Many already-abusive HTTP source IPs hitting the same vhost in one scheduled scan window |
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
| `ip_reputation` | IPs against external threat databases and optional rspamd history |
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
- `wp_bruteforce` -- iterates `/home/*/public_html/*/wp-login.php` and per-domain access logs. The domlog pass ranks recent logs first and honors `thresholds.domlog_max_files`, `thresholds.domlog_tail_lines`, and `thresholds.domlog_max_age_min`.
- `webmail_logins` -- parses cPanel Roundcube/Horde logs
- `mail_queue`, `mail_per_account` -- read Exim queue and `/var/log/exim_mainlog`

**Plain Linux equivalents** that still provide coverage:

- Access log brute-force detection (`wp_login_bruteforce`, `xmlrpc_abuse`) runs against the detected web server's access log (`/var/log/nginx/access.log` or `/var/log/httpd/access_log`), so WordPress brute-force alerts still fire on non-cPanel hosts -- they just rely on the live log watcher rather than per-domain domlog scanning.
- `modsec_audit` runs on any host with ModSecurity installed.
- `ssh_logins`, SSH brute force, PAM listener, firewall, kernel modules, RPM/DEB integrity, and threat intelligence all run on every supported platform.
