# Deep Checks

Deep checks run every 60 minutes and cover thorough filesystem, CMS, email, and database scans.

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
| `exposed_files` | Web-downloadable sensitive files under document roots: database dumps, full-site backup archives, config/credential backups, PHP source-code backups, and `phpinfo.php` diagnostics. Each candidate is reported only after a headers-only reachability probe pinned to the vhost's configured serving IP confirms the server serves it (HTTP 200/206, non-executed body) -- files the server already blocks (403) and shipped samples such as `wp-config-sample.php` are never flagged. The domain is preserved for HTTP Host and TLS SNI, while DNS and front-end proxies are bypassed. The probe reads status and content type only, never the file body. The one exception is `phpinfo.php`: a 200 response alone cannot prove a dump, so CSM reads a bounded portion of that one response and reports `web_exposed_phpinfo` only when it contains real phpinfo output (the `PHP Version` banner in a dump-sized body); stub responses are not findings. Findings: `web_exposed_db_dump`, `web_exposed_backup_archive`, `web_exposed_config_leak`, `web_exposed_source_backup`, `web_exposed_phpinfo`, `web_exposed_sample_sql`. A plain SQL file with a sample/schema-specific name under framework/vendor scaffolding (`examples/`, `docs/`, `vendor/`, unpacked `*-main/` or `*-master/` directories) is reported as the lower-severity `web_exposed_sample_sql` warning. Archived, renamed, customer-named, and other ambiguous dumps stay Critical. Descent depth is bounded by `thresholds.exposed_file_scan_depth` (default 2, maximum 10). Optionally, `auto_response.virtual_patch_exposed_files` (`off`/`manual`/`auto`) writes reversible `.htaccess` `Require all denied` rules -- `manual` applies confirmed findings via `csm virtual-patch --apply`, while `auto` applies every confirmed class except warning-only sample SQL and honors `dry_run`. Recognized backup storage directories are denied as a unit so regenerated archives stay blocked. Each change records a rollback entry; restore refuses to overwrite a later customer edit. |

## WordPress

| Check | Description |
|-------|-------------|
| `wp_core` | Core file integrity via official WordPress.org checksums |
| `nulled_plugins` | Cracked/nulled plugin detection |
| `outdated_plugins` | Plugins behind the latest release, graded by version gap |
| `vulnerable_plugins` | Installed plugins whose version matches a curated known-vulnerable feed (CISA-KEV + confirmed in-the-wild CVEs). Fires only from a fresh shared inventory when a parseable version is inside the affected range; patched, stale, and unparseable versions stay silent. Matched versions are High or Critical regardless of version gap, including inactive plugins because their files remain reachable. Alert-only (never disables a plugin). Toggle `detection.vulnerable_plugin_scanning`; accept one reviewed build via `detection.vulnerable_plugin_allow` (`slug@version`, case-insensitive). |
| `vulnerable_timthumb` | Bundled TimThumb (`timthumb.php` / `thumb.php`) image-resizer scripts, the abandoned library whose remote-code-execution bug (CVE-2011-4106) is a recurring WordPress entry point. Files are confirmed by TimThumb's own constants (not just filename) so generic thumbnail helpers are never flagged. A version below the last patch (`2.8.14`), an unparseable version, or an enabled WebShot / external-fetch feature is reported High; a patched-but-deprecated copy is a Warning to remove. Alert-only -- TimThumb is never auto-quarantined, since deleting it would break the theme. |
| `db_content` | Database injection, siteurl hijacking, rogue admins, spam. Multisite-aware: when `wp-config.php` declares `define('MULTISITE', true)`, secondary blogs (`wp_<N>_options` / `wp_<N>_posts` for active blog IDs from `wp_blogs`) are scanned alongside the unprefixed main-site tables. |
| `db_content_joomla` | Joomla database content scanning. Discovers installs via `configuration.php` containing `class JConfig`, parses credentials from `public $...;` assignments. Scans `<prefix>extensions` params, `<prefix>content` article bodies, and joins `<prefix>users` with `<prefix>user_usergroup_map` for Super User detection (group_id=8). Findings: `joomla_extensions_injection`, `joomla_content_injection`, `joomla_admin_injection`. |
| `db_content_drupal` | Drupal 8+ database content scanning. Discovers installs via `sites/default/settings.php` plus the `core/lib/Drupal.php` marker. Credentials parsed from the `$databases` array. Scans `config`, `node_revision__body`, and `users_field_data` joined with `user__roles` (administrator role). Findings: `drupal_settings_injection`, `drupal_content_injection`, `drupal_admin_injection`. Drupal 7 not yet covered. |
| `db_content_magento` | Magento 1.x and 2.x database content scanning. Discovers installs via `app/etc/env.php` (M2, preferred) or `app/etc/local.xml` (M1). Credentials parsed via `encoding/xml` for M1 (CDATA-aware) or field-level regex for M2. Scans `core_config_data`, `catalog_product_entity_text`, `cms_block`, `cms_page`, and `admin_user` (with the configured `db.prefix`). Findings: `magento_settings_injection`, `magento_content_injection`, `magento_admin_injection`. |
| `db_content_opencart` | OpenCart database content scanning. Discovers installs via the `config.php` + `admin/config.php` pair both containing `define('DB_DRIVER'`. Credentials parsed from `DB_HOSTNAME` / `DB_USERNAME` / `DB_PASSWORD` / `DB_DATABASE` / `DB_PREFIX` defines. Scans `<prefix>setting` (`config_url` / `config_ssl` are canonical hijack targets), `<prefix>product_description`, `<prefix>information_description`, and `<prefix>user` (admin/staff). Findings: `opencart_settings_injection`, `opencart_content_injection`, `opencart_admin_injection`. |
| `db_objects` | MySQL persistence mechanisms: triggers, events, stored procedures, stored functions. Critical when the body matches known-malware patterns (`sys_`+`exec`, `INTO OUTFILE`, `LOAD_FILE`, etc.); Warning when an object exists at all (vanilla CMSes ship none). Toggle with `detection.db_object_scanning`; suppress Warnings via `detection.db_object_allowlist`. Manual drop via `csm db-clean --drop-object`. |
| `admin_overlap` | WordPress administrator email overlap across cPanel accounts. Reports when the same admin email appears on the configured number of accounts, with reviewed emails and domains suppressible in `detection`. |
| `credential_reuse` | WordPress administrator password-hash reuse across cPanel accounts. Groups identical hashes with an in-memory fingerprint and reports only the affected accounts and count. |
| `supply_chain` | Composer and npm lockfile advisory matching against the local advisory database. Silent when no advisory file is present. |

## CMS Scanner Support Policy

New CMS scanner work targets upstream-supported major versions. EOL versions are best-effort when the existing scanner covers them through the same low-risk layout or schema. Adding a new EOL-only scanner needs operator fleet data and an explicit security reason.

Current scanner scope:

- WordPress single-site and multisite.
- Joomla installs using the common `configuration.php` / `JConfig` layout and standard content/user tables used by supported Joomla releases.
- Drupal 8 and newer. Drupal 7 is not a planned support target.
- Magento 1 and 2.
- OpenCart installs using the standard storefront and admin config pair.

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
| `dns_zones` | Security-sensitive DNS zone changes (delegation, mail, apex, and wildcard records) |
| `ssl_certs` | SSL certificate issuance (subdomain takeover) |
| `waf_status` | WAF mode, staleness, bypass detection |

## Email Security

| Check | Description |
|-------|-------------|
| `email_weak_password` | Email accounts with weak passwords |
| `email_forwarder_audit` | Forwarders redirecting to external addresses |
| `email_mail_filters` | Exim mail filters that intercept mail (copy to an external address while keeping a local copy), forward externally, pipe to a command, or blackhole all mail |

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
- `supply_chain` -- scans `composer.lock` and `package-lock.json` under `/home/*` and `/home/*/public_html`
- `phishing`, `email_content` -- scan user home directories and Exim spool
- `dns_zones`, `ssl_certs` -- read cPanel's DNS zone store and SSL installation records
- `email_weak_password`, `email_forwarder_audit` -- read `/etc/valiases`, Dovecot/Courier auth databases
- `email_mail_filters` -- read per-mailbox Exim filters under `/home/*/etc/<domain>/<localpart>/filter` and domain filters under `/etc/vfilters`
- `open_basedir`, `php_config_changes` -- read EA-PHP `php.ini` under `/opt/cpanel/ea-php*/`
- `perf_wp_config`, `perf_wp_transients`, `perf_wp_cron`, `perf_php_handler` -- WordPress and PHP handler introspection via cPanel's EA-PHP layout

**Runs on every platform:**

- `filesystem`, `webshells` -- fanotify and file-tree scans over `/home`, `/tmp`, `/dev/shm`
- `rpm_integrity` -- dispatches to `rpm -V` on RHEL family or `debsums` / `dpkg --verify` on Debian family
- `waf_status` -- detects ModSecurity on Apache, Nginx, and LiteSpeed across all supported distros
- `perf_mysql_config`, `perf_redis_config`, `perf_error_logs` -- rely on standard service locations

Operators on plain Linux can point `perf_error_logs`, `perf_wp_config`, `perf_wp_transients`, and `perf_wp_cron` at generic web roots with the `account_roots` glob list (see [configuration.md](configuration.md)). The remaining account and CMS scans still assume the cPanel `/home/*/public_html` layout.
