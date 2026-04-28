# Deep Checks

28 checks, run every 60 minutes. Thorough filesystem and database scans.

## Filesystem

| Check | Description |
|-------|-------------|
| `filesystem` | Backdoors, hidden executables, suspicious SUID binaries |
| `webshells` | Known webshell patterns (c99, r57, b374k, etc.) |
| `htaccess` | .htaccess injection (auto_prepend_file, eval, base64 handlers) plus seven hardened per-pattern detectors -- `htaccess_php_in_uploads`, `htaccess_auto_prepend`, `htaccess_user_agent_cloak`, `htaccess_spam_redirect`, `htaccess_filesmatch_shield`, `htaccess_header_injection`, `htaccess_errordocument_hijack`. Auto-cleaning gated by `auto_response.clean_htaccess`. |
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
| `db_content` | Database injection, siteurl hijacking, rogue admins, spam. Multisite-aware: when `wp-config.php` declares `define('MULTISITE', true)`, secondary blogs (`wp_<N>_options` / `wp_<N>_posts` for active blog IDs from `wp_blogs`) are scanned alongside the unprefixed main-site tables. |
| `db_content_joomla` | Joomla database content scanning. Discovers installs via `configuration.php` containing `class JConfig`, parses credentials from `public $...;` assignments. Scans `<prefix>extensions` params, `<prefix>content` article bodies, and joins `<prefix>users` with `<prefix>user_usergroup_map` for Super User detection (group_id=8). Findings: `joomla_extensions_injection`, `joomla_content_injection`, `joomla_admin_injection`. |
| `db_objects` | MySQL persistence mechanisms: triggers, events, stored procedures, stored functions. Critical when the body matches known-malware patterns (`sys_`+`exec`, `INTO OUTFILE`, `LOAD_FILE`, etc.); Warning when an object exists at all (vanilla CMSes ship none). Toggle with `detection.db_object_scanning`; suppress Warnings via `detection.db_object_allowlist`. Manual drop via `csm db-clean --drop-object`. |

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

## Platform Support

The deep checks are the most cPanel-biased part of CSM because they iterate account home directories and per-user public_html trees. On plain Ubuntu/AlmaLinux the account-scan based checks do not run today:

**cPanel-only** (skipped on plain Linux):

- `htaccess`, `file_index`, `php_content`, `group_writable_php`, `symlink_attacks` -- iterate `/home/*/public_html/**`
- `wp_core`, `nulled_plugins`, `outdated_plugins`, `db_content` -- find WordPress installs under `/home/*/public_html`
- `phishing`, `email_content` -- scan user home directories and Exim spool
- `dns_zones`, `ssl_certs` -- read cPanel's DNS zone store and SSL installation records
- `email_weak_password`, `email_forwarder_audit` -- read `/etc/valiases`, Dovecot/Courier auth databases
- `open_basedir`, `php_config_changes` -- read EA-PHP `php.ini` under `/opt/cpanel/ea-php*/`
- `perf_wp_config`, `perf_wp_transients`, `perf_wp_cron`, `perf_php_handler` -- WordPress and PHP handler introspection via cPanel's EA-PHP layout

**Runs on every platform:**

- `filesystem`, `webshells` -- fanotify and file-tree scans over `/home`, `/tmp`, `/dev/shm`
- `rpm_integrity` -- dispatches to `rpm -V` on RHEL family or `debsums` / `dpkg --verify` on Debian family
- `waf_status` -- detects ModSecurity on Apache, Nginx, and LiteSpeed across all supported distros
- `perf_mysql_config`, `perf_redis_config`, `perf_error_logs` -- rely on standard service locations

Operators on plain Linux can opt a subset of the account-scan perf checks (`perf_error_logs`, `perf_wp_config`, `perf_wp_transients`) into scanning generic webroots by configuring the `account_roots` glob list in `csm.yaml` (see [configuration.md](configuration.md)). The remaining account-scan checks still assume the cPanel `/home/*/public_html` layout.
