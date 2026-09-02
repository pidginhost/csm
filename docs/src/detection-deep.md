# Deep Checks

Deep checks run every 60 minutes and cover thorough filesystem, CMS, email, and database scans.

## Filesystem

| Check | Description |
|-------|-------------|
| `filesystem` | Backdoors, hidden executables, suspicious SUID binaries |
| `webshells` | Known webshell patterns (c99, r57, b374k, etc.) |
| `htaccess` | .htaccess injection (auto_prepend_file, eval, base64 handlers) plus nine hardened per-pattern detectors -- `htaccess_php_in_uploads`, `htaccess_auto_prepend`, `htaccess_user_agent_cloak`, `htaccess_spam_redirect`, `htaccess_filesmatch_shield`, `htaccess_header_injection`, `htaccess_errordocument_hijack`, `htaccess_cgi_handler_abuse`, `htaccess_security_disabled`. Auto-cleaning gated by `auto_response.clean_htaccess`. |
| `file_index` | Indexed file listing to detect new/unauthorized files |
| `php_content` | Suspicious PHP functions (exec, eval, system, passthru) |
| `group_writable_php` | World/group-writable PHP files (privilege escalation) |
| `js_keylogger_dataflow` | JavaScript keystroke exfiltration found by AST data-flow analysis: a key-event value that reaches fetch, sendBeacon, XHR, WebSocket, or a resource `.src` sink, including flows laundered through variables that regex rules cannot express. Runs inside the scheduled deep scan on the same file snapshots as the YARA pass but independent of the YARA backend, with its own rolling cursor. Complete sources up to 2 MiB are analyzed; a file the analyzer could not complete (oversize, parse failure, resource limit) is reported in the Warning-level `js_taint_scan_incomplete` aggregate and its prior finding is preserved, never silently cleared. Disable with `js_keylogger_dataflow` (or the owner ID `js_taint_deep`) in `disabled_checks`; disabling the YARA scan does not disable this analyzer. |
| `symlink_attacks` | Symlink-based privilege escalation attempts |
| `exposed_files` | Web-downloadable sensitive files under document roots: version-control directories (`.git/`, `.svn/`, reported as `web_exposed_repo_metadata` and virtual-patched by denying the whole directory), database dumps, full-site backup archives, config/credential backups, PHP source-code backups, and `phpinfo.php` diagnostics. Each candidate is reported only after a headers-only reachability probe pinned to the vhost's configured serving IP confirms the server serves it (HTTP 200/206, non-executed body) -- files the server already blocks (403) and shipped samples such as `wp-config-sample.php` are never flagged. The domain is preserved for HTTP Host and TLS SNI, while DNS and front-end proxies are bypassed. The probe reads status and content type only, never the file body. The one exception is `phpinfo.php`: a 200 response alone cannot prove a dump, so CSM reads a bounded portion of that one response and reports `web_exposed_phpinfo` only when it contains real phpinfo output (the `PHP Version` banner in a dump-sized body); stub responses are not findings. Findings: `web_exposed_db_dump`, `web_exposed_backup_archive`, `web_exposed_config_leak`, `web_exposed_source_backup`, `web_exposed_phpinfo`, `web_exposed_sample_sql`. A plain SQL file with a sample/schema-specific name under framework/vendor scaffolding (`examples/`, `docs/`, `vendor/`, unpacked `*-main/` or `*-master/` directories) is reported as the lower-severity `web_exposed_sample_sql` warning. Archived, renamed, customer-named, and other ambiguous dumps stay Critical. Descent depth is bounded by `thresholds.exposed_file_scan_depth` (default 2, maximum 10). Optionally, `auto_response.virtual_patch_exposed_files` (`off`/`manual`/`auto`) writes reversible `.htaccess` `Require all denied` rules -- `manual` applies confirmed findings via `csm virtual-patch --apply`, while `auto` applies every confirmed class except warning-only sample SQL and honors `dry_run`. Recognized backup storage directories are denied as a unit so regenerated archives stay blocked. A zip whose name carries no backup wording is classified from its central directory instead, so an archive named after the site it holds is reported when it contains a site-root or structured CMS configuration path, a document-root directory, or a database dump at the archive root; plugin and theme bundles offered as ordinary downloads stay quiet. The complete entry list is inspected within a fixed metadata budget, without extracting or decompressing payloads; an archive that exceeds the budget leaves the scan incomplete instead of silently clearing an earlier finding. Each change records a rollback entry; restore refuses to overwrite a later customer edit. |

## PHP Remote-Source Taint Analysis

This analyzer runs as part of the scheduled deep-content scan, alongside the YARA and JavaScript consumers, and reports `php_remote_taint`. Disable it with `php_taint_deep` (or `php_remote_taint`) in `disabled_checks`.

**It runs in a separate process, and that is not an implementation detail.** A single file can put the underlying PHP parser into a state it never returns from, which no in-process deadline can interrupt. Analysis therefore happens in a supervised child process that is killed outright when a file exceeds its deadline; that file is reported as reduced coverage and the scan continues. Repeated failures are rate-limited so no single account can consume the scan budget, and the analyzer recovers without operator action. Whenever a file cannot be examined -- including when no worker is available -- it is reported as unexamined, never as clean.

CSM includes a PHP analyzer that looks for code fetching content from a remote server and then executing it, even when the fetch and the execution happen in different functions. This is a flow that regular expressions cannot express: matching it requires binding the value a fetch returns to the value handed to execution, which is beyond what YAML pattern rules or YARA-X can do.

The analyzer parses PHP source and tracks whether a value returned by a remote-fetching call reaches a code-execution construct (`eval`, `include`, `include_once`, `require`, `require_once`, `create_function`, or `assert` given a string argument), following the value through variable assignment, string concatenation, decoding calls, across function and method boundaries, and through a `file_put_contents` write into an `include` of the same path expression. `curl_exec`, `curl_multi_getcontent`, `wp_remote_get`, `wp_remote_retrieve_body`, and `fsockopen` are always treated as a remote source, whatever their argument. `file_get_contents` and `fopen` are dual-use: only these two calls have their argument inspected, and only when that argument carries an HTTP, HTTPS, FTP, FTPS, `php://input`, or `data://` scheme are they classified as a remote source rather than a local read. Not every `php://` stream counts as remote: `php://input` is request-controlled and treated as a source, while `php://memory`, `php://temp`, and a local `php://filter` resource are not -- though a filter wrapping a remote resource still carries its nested remote scheme and is classified accordingly. A URL used directly as a sink's own argument, with no acquiring call in between -- `include 'http://evil/x.php'` -- is out of scope: the pre-filter requires a source keyword before parsing is even attempted, and a bare remote include has none, so it is reported `not_candidate`, not analyzed.

Only two outcomes mean a file was actually examined: **analyzed** (parsing and the data-flow pass both completed) and **not candidate** (a fast pre-check proved the file cannot contain a reportable flow, without needing to parse it). Every other outcome -- oversize, a parse failure, a parser recovery that produced only a partial tree, an internal resource limit, cancellation, or an internal error -- is a coverage gap, not a clean result, and must never be read as "nothing to see here."

A finding's severity follows how firmly the source was shown to be remote: a decoder-confirmed remote fetch reaching execution is Critical, a fetch carrying a remote URL is High, and a dual-use call whose argument could not be resolved either way is a Warning for review. When one file contains several flows, its strongest flow sets the severity. The last group is where legitimate template compilers and cache layers land, so it is kept visible without paging anyone.

Coverage the scan could not reach is reported as `php_taint_scan_incomplete`, which names how many files were affected and why -- a per-file status such as a timeout or a worker failure, or a location the walk could not read at all, where the affected files cannot even be listed. Panics and timeouts are reported in a separate aggregate so hard analyzer failures remain visible beside routine coverage limits. A file that had a finding and later becomes unexaminable keeps its previous finding rather than having it cleared.

Separately from the outcome, an analyzed file can still report reduced precision. Constructs that defeat static variable identity -- `extract()`, `compact()`, variable variables, a call dispatched through a value, an assignment target the analyzer cannot name, or a value a closure or arrow function captures from its enclosing scope -- are recorded alongside the result. A recorded loss means tracking stopped at that point and the file may hold a flow that was not followed; it is never left implicit. The capture case is recorded only when the captured value was itself tainted, so it marks a real loss rather than the mere presence of a closure.

The parser supports PHP syntax up to version 8.1. A file written against a newer PHP version may use constructs the parser does not recognize; when that happens, parsing recovers what it can but the result is incomplete, and the file is reported as reduced coverage (a partial parse) rather than analyzed, so an incomplete view is never presented as a complete one.

## WordPress

| Check | Description |
|-------|-------------|
| `wp_core` | Core file integrity via official WordPress.org checksums |
| `nulled_plugins` | Cracked/nulled plugin detection |
| `outdated_plugins` | Plugins behind the latest release, graded by version gap |
| `vulnerable_plugins` | Installed plugins whose version matches a curated known-vulnerable feed (CISA-KEV + confirmed in-the-wild CVEs). Fires only from a fresh shared inventory when a parseable version is inside the affected range; patched, stale, and unparseable versions stay silent. Matched versions are High or Critical regardless of version gap, including inactive plugins because their files remain reachable. Alert-only (never disables a plugin). Toggle `detection.vulnerable_plugin_scanning`; accept one reviewed build via `detection.vulnerable_plugin_allow` (`slug@version`, case-insensitive). For an active install, a host engine that is `Off` or `DetectionOnly`, or a disabled account or vhost scope, marks the finding unprotected and raises it to Critical: no request filtering applies and no modsec audit record is written. When CSM ships a virtual patch for that CVE (`virtual_patch` in the feed) the alert says that patch cannot run; otherwise it claims only the filtering gap. An inactive install is never annotated -- its files are why it is reported, but WordPress does not load the vulnerable code path, so a missing filter says nothing about reachability. An addon domain is linked only to its exact cPanel-associated subdomain; unrelated parked, main, and addon sites that happen to share a document root do not inherit one another's disabled flags. Off cPanel, where CSM deploys no virtual patches and no per-vhost ModSecurity state exists, findings are left as the detector graded them. |
| `vulnerable_timthumb` | Bundled TimThumb (`timthumb.php` / `thumb.php`) image-resizer scripts, the abandoned library whose remote-code-execution bug (CVE-2011-4106) is a recurring WordPress entry point. Files are confirmed by TimThumb's own constants (not just filename) so generic thumbnail helpers are never flagged. A version below the last patch (`2.8.14`), an unparseable version, or an enabled WebShot / external-fetch feature is reported High; a patched-but-deprecated copy is a Warning to remove. The final release is suppressed only when `ALLOW_EXTERNAL`, `ALLOW_ALL_EXTERNAL_SITES`, and `WEBSHOT_ENABLED` are defined as false in executable PHP and none is also defined as true. Alert-only -- TimThumb is never auto-quarantined, since deleting it would break the theme. |
| `db_content` | Database injection (an external script loader on an ordinary HTTPS host that carries no attacker marker is reported once, as a Warning `db_options_new_external_script`, the first time that host appears in an option after the site's first scan), siteurl hijacking, rogue admins, spam, a sudden publishing flood measured against the site's own history (`db_post_volume_burst`; only on sites older than 400 days, with at least 50 recent posts and more than 5x everything published before -- a genuine content migration looks the same, so it is alert-only), spam categories, tags and other taxonomy terms left behind when spam posts are removed (`db_spam_taxonomy`; a term named after a URL is High, spam vocabulary alone is Warning), PHP-capable snippets stored in the database by WPCode (`db_stored_code_execution`, Critical when the snippet is published and therefore running, lower when it is a draft or trashed; stored code is invisible to filesystem scanning), outbound links wrapped in a container the page hides from readers (`db_hidden_link_injection`; an off-canvas container -- a large negative `left`/`top`/`text-indent` -- is High on its own, while `display:none`, `visibility:hidden` and fully transparent opacity need corroboration from a second linked domain in the same container or spam vocabulary, because themes legitimately hide panels that link out. Links back to the site's own registrable domain are ignored, and the scan is skipped when `siteurl`/`home` cannot be read, since every absolute link would then look external. Markup is tokenized rather than parsed into a tree, so nesting the injection past a tree parser's open-element limit does not hide it), autoloaded options named by a 32-character hex digest whose value base64-decodes to one complete PHP-serialized array (`db_hostname_keyed_option`; kits key the digest to the site's own hostname so one payload serves many sites, and both halves are required because plugins do write hashed cache keys and base64 alone is ordinary), rewrite rules pairing an exact `sitemap<N>.xml` route with `feed=xmlsitemap<N>` in the same rule (`db_doorway_sitemap_routes`; sitemap plugins add numbered rewrite rules too, so the matching number is what distinguishes a doorway cluster from paginated sitemaps). Bounded option reads that omit any stored bytes mark the scan incomplete, and that row does not produce a finding. The scan also reports published posts attributed to a user that does not exist (`db_phantom_post_author`, Critical at 100 posts or more and Warning below). Small orphan groups can result from direct SQL user deletion; large groups can identify doorway content whose invented author IDs are hidden from dashboard queries. Direct WordPress installs are covered at every document root the panel serves and at every addon-domain directory in an account home, so a root the panel has stopped serving is still examined; account backup and metadata directories are not, and ordinary subdirectory installs are not discovered recursively. A site address is reported when its shape cannot be one -- a missing host, an invalid port, a backslash, a query string, a fragment, a script for a path, or a non-web scheme -- because WordPress builds every asset URL from it. Invalid-address findings are alert-only; only explicit code injection enters database auto-response. Serving a site under a domain hosted elsewhere is ordinary and is not reported. Multisite-aware: when `wp-config.php` declares `define('MULTISITE', true)`, up to 100 active secondary blogs (`wp_<N>_options` / `wp_<N>_posts` for blog IDs from `wp_blogs`) are scanned alongside the unprefixed main-site tables; each blog's PHP-capable WPCode snippets and taxonomy are scanned, and its posts are checked against the network-wide users table. Larger networks emit `db_content_scan_incomplete` and retain prior findings. |
| `db_content_joomla` | Joomla database content scanning. Discovers installs via `configuration.php` containing `class JConfig`, parses credentials from `public $...;` assignments. Scans `<prefix>extensions` params, `<prefix>content` article bodies, and joins `<prefix>users` with `<prefix>user_usergroup_map` for Super User detection (group_id=8). Findings: `joomla_extensions_injection`, `joomla_content_injection`, `joomla_admin_injection`. Administrator rows are baselined on the first pass; only an administrator that appears later is reported, once, as High. Every query is capped at 200 rows and runs under the scan deadline; installs under addon-domain document roots are discovered too. |
| `db_content_drupal` | Drupal 8+ database content scanning. Discovers installs via `sites/default/settings.php` plus the `core/lib/Drupal.php` marker. Credentials parsed from the `$databases` array. Scans `config`, `node_revision__body`, and `users_field_data` joined with `user__roles` (administrator role). Findings: `drupal_settings_injection`, `drupal_content_injection`, `drupal_admin_injection`. Administrator rows are baselined on the first pass; only an administrator that appears later is reported, once, as High. Every query is capped at 200 rows and runs under the scan deadline; installs under addon-domain document roots are discovered too. Drupal 7 not yet covered. |
| `db_content_magento` | Magento 1.x and 2.x database content scanning. Discovers installs via `app/etc/env.php` (M2, preferred) or `app/etc/local.xml` (M1). Credentials parsed via `encoding/xml` for M1 (CDATA-aware) or field-level regex for M2. Scans `core_config_data`, `catalog_product_entity_text`, `cms_block`, `cms_page`, and `admin_user` (with the configured `db.prefix`). Findings: `magento_settings_injection`, `magento_content_injection`, `magento_admin_injection`. Administrator rows are baselined on the first pass; only an administrator that appears later is reported, once, as High. Every query is capped at 200 rows and runs under the scan deadline; installs under addon-domain document roots are discovered too. |
| `db_content_opencart` | OpenCart database content scanning. Discovers installs via the `config.php` + `admin/config.php` pair both containing `define('DB_DRIVER'`. Credentials parsed from `DB_HOSTNAME` / `DB_USERNAME` / `DB_PASSWORD` / `DB_DATABASE` / `DB_PREFIX` defines. Scans `<prefix>setting` (`config_url` / `config_ssl` are canonical hijack targets), `<prefix>product_description`, `<prefix>information_description`, and `<prefix>user` (admin/staff). Findings: `opencart_settings_injection`, `opencart_content_injection`, `opencart_admin_injection`. Administrator rows are baselined on the first pass; only an administrator that appears later is reported, once, as High. Every query is capped at 200 rows and runs under the scan deadline; installs under addon-domain document roots are discovered too. |
| `db_objects` | MySQL persistence mechanisms: triggers, events, stored procedures, stored functions. Critical when the body matches known-malware patterns (`sys_`+`exec`, `INTO OUTFILE`, `LOAD_FILE`, etc.); Warning when an object exists at all (vanilla CMSes ship none). Toggle with `detection.db_object_scanning`; suppress Warnings via `detection.db_object_allowlist`. Manual drop via `csm db-clean --drop-object`. |
| `admin_overlap` | WordPress administrator email overlap across cPanel accounts. Reports when the same admin email appears on the configured number of accounts, with reviewed emails and domains suppressible in `detection`. |
| `credential_reuse` | WordPress administrator password-hash reuse across cPanel accounts. Groups identical hashes with an in-memory fingerprint and reports only the affected accounts and count. |
| `supply_chain` | Composer and npm lockfile advisory matching against the local advisory database. Silent when no advisory file is present. |

Hidden-link corroboration counts registrable domains within one hidden container, not hostnames across a whole row. Multiple subdomains of one linked domain count as one target, and both the WordPress home and site addresses count as local.

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
| `php_config_changes` | Security-weakening `.user.ini` and `php.ini` files under account web roots |

## DNS & SSL

| Check | Description |
|-------|-------------|
| `dns_zones` | Security-sensitive DNS zone changes (delegation, mail, apex, and wildcard records) |
| `ssl_certs` | SSL certificate issuance (subdomain takeover) |
| `waf_status` | WAF mode, staleness, bypass detection. On cPanel, staleness follows vendor configuration files that WHM reports as active and ignores retired trees that remain on disk; the warning means at least one loaded vendor has not refreshed in over a month. Other platforms keep the conservative oldest-artifact check so an unused fresh tree cannot hide stale loaded rules. |

## Email Security

| Check | Description |
|-------|-------------|
| `email_weak_password` | Email accounts with weak passwords |
| `email_forwarder_audit` | Forwarders redirecting to external addresses |
| `email_mail_filters` | Exim mail filters and dovecot/Roundcube Sieve scripts that copy mail to an external address while keeping a local copy, forward externally, pipe to a command, or blackhole all mail. Sieve is what webmail-managed rules actually execute, so both are scanned. A forward that leaves the mailbox its own copy is what a webmail forward rule produces, so on its own it reports as a Warning for review; it is Critical when an independent forwarding layer on the same mailbox, mail the mailbox never receives, or the same destination across accounts corroborates it. |

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
- `open_basedir` -- reads EA-PHP `php.ini` under `/opt/cpanel/ea-php*/`
- `php_config_changes` -- recursively scans `.user.ini` and `php.ini` below account web roots; incomplete walks emit a coverage finding and preserve prior findings
- `perf_wp_config`, `perf_wp_transients`, `perf_wp_cron`, `perf_php_handler` -- WordPress and PHP handler introspection via cPanel's EA-PHP layout; the WP-Cron check also uses cPanel's domain map for addon and subdomain roots

**Runs on every platform:**

- `filesystem`, `webshells` -- fanotify and file-tree scans over `/home`, `/tmp`, `/dev/shm`
- `rpm_integrity` -- dispatches to `rpm -V` on RHEL family or `debsums` / `dpkg --verify` on Debian family
- `waf_status` -- detects ModSecurity on Apache, Nginx, and LiteSpeed across all supported distros
- `perf_mysql_config`, `perf_redis_config`, `perf_error_logs` -- rely on standard service locations

Operators on plain Linux can point `perf_error_logs`, `perf_wp_config`, `perf_wp_transients`, and `perf_wp_cron` at generic web roots with the `account_roots` glob list (see [configuration.md](configuration.md)). The remaining account and CMS scans still assume the cPanel `/home/*/public_html` layout.
