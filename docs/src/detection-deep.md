# Deep Checks

28 checks, run every 60 minutes. Thorough filesystem and database scans.

## Filesystem

| Check | Description |
|-------|-------------|
| `filesystem` | Backdoors, hidden executables, suspicious SUID binaries |
| `webshells` | Known webshell patterns (c99, r57, b374k, etc.) |
| `htaccess` | .htaccess injection (auto_prepend_file, eval, base64 handlers) |
| `file_index` | Indexed file listing to detect new/unauthorized files |
| `php_content` | Suspicious PHP functions (exec, eval, system, passthru) |
| `group_writable_php` | World/group-writable PHP files (privilege escalation) |
| `symlink_attacks` | Symlink-based privilege escalation attempts |

## WordPress

| Check | Description |
|-------|-------------|
| `wp_core` | Core file integrity via official WordPress.org checksums |
| `nulled_plugins` | Cracked/nulled plugin detection |
| `outdated_plugins` | Plugins with known CVEs |
| `db_content` | Database injection, siteurl hijacking, rogue admins, spam |

## Phishing & Malware

| Check | Description |
|-------|-------------|
| `phishing` | 8-layer phishing detection (kit directories, credential harvesting) |
| `email_content` | Outbound email body scanning for credentials and suspicious URLs |

## System Integrity

| Check | Description |
|-------|-------------|
| `rpm_integrity` | System binary verification via rpm -V |
| `open_basedir` | open_basedir restriction validation |
| `php_config_changes` | php.ini modifications |

## DNS & SSL

| Check | Description |
|-------|-------------|
| `dns_zones` | DNS zone file changes (MX record hijacking) |
| `ssl_certs` | SSL certificate issuance (subdomain takeover) |
| `waf_status` | WAF mode, staleness, bypass detection |

## Email Security

| Check | Description |
|-------|-------------|
| `email_weak_password` | Email accounts with weak passwords |
| `email_forwarder_audit` | Forwarders redirecting to external addresses |

## Performance

| Check | Description |
|-------|-------------|
| `perf_php_handler` | PHP handler configuration (DSO vs CGI vs FPM) |
| `perf_mysql_config` | MySQL my.cnf optimization |
| `perf_redis_config` | Redis configuration |
| `perf_error_logs` | Error log file growth (bloat) |
| `perf_wp_config` | WordPress wp-config.php settings |
| `perf_wp_transients` | WordPress database transient bloat |
| `perf_wp_cron` | WordPress cron scheduling (missed crons) |
