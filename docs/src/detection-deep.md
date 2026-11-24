# Deep Checks

Deep checks run every 60 minutes. They are the thorough scans of the filesystem, CMS installs, email and databases.

The tables on this page list every check by family. Where a check needs more than one line, a section under its table gives the rules. Most deep checks need cPanel: [Platform Support](#platform-support) lists which ones run elsewhere. [Details](#details) at the end collects edge cases.

## How scans are scheduled

Scheduled checks and account scan checks share one budget inside the daemon. CSM sizes it from the machine's core count: at least two and at most five checks run at the same time.

- Web UI scans and CLI jobs submitted with `csm scan --full` share this budget.
- Standalone CLI scans run in a separate process.
- A cancelled or timed-out check keeps its slot until it actually exits, while its caller can return promptly.
- A check that waits for a slot held by another scan is not reported as a stalled queue in the queue health status.

The real-time scanner has a separate pool of two to sixteen workers, also sized from the core count. With at least two workers, other events progress while one content scan is slow.

Both the packaged service unit and the installer-generated one give CSM a lower CPU weight than the default. Under contention this favors sibling services that have the default weight. On an idle host, scans can still use spare CPU. It is not a CPU quota.

## Filesystem

| Check | Description |
|-------|-------------|
| `filesystem` | Backdoors, hidden executables, suspicious SUID binaries. See [Hidden temporary files](#hidden-temporary-files). |
| `webshells` | Known webshell patterns (c99, r57, b374k, etc.) |
| `htaccess` | .htaccess injection (auto_prepend_file, eval, base64 handlers), plus ten hardened per-pattern detectors. See [.htaccess checks](#htaccess-checks). |
| `file_index` | Indexed file listing to detect new/unauthorized files |
| `php_content` | Suspicious PHP functions (exec, eval, system, passthru) |
| `group_writable_php` | World/group-writable PHP files (privilege escalation) |
| `js_keylogger_dataflow` | JavaScript keystroke exfiltration found by AST data-flow analysis. See [JavaScript keylogger analysis](#javascript-keylogger-analysis). |
| `symlink_attacks` | Symlink-based privilege escalation attempts |
| `exposed_files` | Web-downloadable sensitive files under document roots. See [Exposed files](#exposed-files). |

### Scans that run on every deep cycle

The webshell, .htaccess, phishing and filesystem scans run on every deep cycle, alongside the file index. They run while the realtime monitor is active too, because the monitor misses two things. It does not report a setuid bit being set. It sees files renamed or linked into place only where a placement backend runs.

The file index runs on every deep cycle too, including while the realtime monitor is active. It checks new paths and checks again the indexed files that have active findings. Being present in the baseline does not clear an alert.

The exposed-file scan runs in the same tier on its own interval. See [When the exposed-file scan runs](#when-the-exposed-file-scan-runs).

### Incomplete scans keep earlier findings

These problems leave the affected scan incomplete:

- Account discovery fails.
- A directory or file cannot be read.
- The backdoor candidate list is truncated.

The scan's earlier findings stay active until a complete scan can replace them. Detections from the incomplete attempt are still added. Both rules hold whether or not the realtime monitor is active.

### .htaccess checks

The `htaccess` check combines a generic scanner with ten per-pattern detectors. The generic scanner reports `htaccess_injection` and `htaccess_handler_abuse`. Each per-pattern detector reports under its own name:

- `htaccess_php_in_uploads`
- `htaccess_auto_prepend`
- `htaccess_user_agent_cloak`
- `htaccess_spam_redirect`
- `htaccess_filesmatch_shield`
- `htaccess_rewrite_off_shield`
- `htaccess_header_injection`
- `htaccess_errordocument_hijack`
- `htaccess_cgi_handler_abuse`
- `htaccess_security_disabled`

| Finding type | How it is cleaned and re-checked |
|--------------|----------------------------------|
| Per-pattern finding | The per-pattern audit handles cleaning and re-checks. |
| Generic finding | The generic scanner plus the per-pattern detectors handle its manual fix and re-check. |

Realtime detection uses the combined audit too: the generic scanner plus the per-pattern detectors.

#### Automatic .htaccess cleaning

Automatic cleaning runs only when `auto_response.clean_htaccess` is on.

- It acts on the per-pattern findings and on `htaccess_handler_abuse`. That finding is a handler mapping for a file extension that no site uses.
- It removes only the directives of those findings.
- Other generic `htaccess_injection` findings keep the manual fix.
- No `.htaccess` finding is handled by file quarantine.
- Automatic cleaning needs directives it can remove. A prepend directive that the cleaner leaves in place stays reported and does not enter the automatic response budget.
- Oversized files stay unchanged and need manual inspection. A re-check cannot declare them clean.

Manual removal of a malicious rewrite also removes its condition chain, so the conditions cannot affect the next rule.

[.htaccess detection rules](#htaccess-detection-rules) lists what each detector reports and what it leaves alone.

### JavaScript keylogger analysis

`js_keylogger_dataflow` finds JavaScript that sends keystrokes away. It uses AST data-flow analysis: it follows a key-event value until it reaches a fetch, sendBeacon, XHR, WebSocket, or resource `.src` sink. That includes flows laundered through variables, which regex rules cannot express.

The analyzer also detects keystroke leaks in modules that use import or export attributes. It traces leaks through destructured arrow parameter defaults and through statements whose semicolon starts the next line.

It runs inside the scheduled deep scan, on the same file snapshots as the YARA pass. It is independent of the YARA backend and has its own rolling cursor.

To turn it off, add `js_keylogger_dataflow` (or the owner ID `js_taint_deep`) to `disabled_checks`. Disabling the YARA scan does not disable this analyzer.

#### Which files it analyzes

Classification uses content, not file extensions.

| File | What the analyzer does |
|------|------------------------|
| Complete source up to 2 MiB | Analyzes it. |
| Valid candidate JavaScript whose comments or strings contain document markers | Always analyzes it. |
| Recognized PHP and HTML documents (including HTML-first PHP templates), complete JSON/source maps, CSS stylesheets, gettext catalogs | Skips them. They do not count as JavaScript parse failures. |
| JavaScript embedded in templates or data files | Does not extract or analyze it. |
| Ambiguous source, or malformed JavaScript | Keeps its coverage warning. |
| Oversize source | Keeps the size-limit warning. |

PHP analysis and content rules do not provide equivalent JavaScript data-flow coverage for embedded JavaScript.

A file the analyzer could not complete (oversize, parse failure, resource limit) is reported in the Warning-level `js_taint_scan_incomplete` aggregate. Its prior finding is preserved, never silently cleared.

### Exposed files

`exposed_files` reports sensitive files under a document root that anyone can download from the web.

| Finding | What is exposed |
|---------|-----------------|
| `web_exposed_repo_metadata` | A version-control directory: `.git/` or `.svn/`. |
| `web_exposed_db_dump` | A database dump. |
| `web_exposed_backup_archive` | A full-site backup archive. |
| `web_exposed_config_leak` | A config or credential backup. |
| `web_exposed_source_backup` | A PHP source-code backup. |
| `web_exposed_phpinfo` | A `phpinfo.php` diagnostics page. |
| `web_exposed_sample_sql` | A sample SQL file under framework or vendor scaffolding. Lower severity: a Warning. |

The scan goes at most `thresholds.exposed_file_scan_depth` directories deep (default 2, maximum 10).

#### How CSM confirms an exposure

CSM reports a candidate only after a reachability probe confirms that the server serves it.

- The probe is pinned to the vhost's configured serving IP. It keeps the domain for HTTP Host and TLS SNI, and bypasses DNS and front-end proxies.
- The probe is headers-only. It reads status and content type, never the file body.
- HTTP 200 or 206 with a non-executed body confirms the exposure.
- Files the server already blocks (403) are never flagged.
- Shipped samples such as `wp-config-sample.php` are never flagged.

`phpinfo.php` is the one exception to the headers-only rule. A 200 response alone cannot prove a dump, so CSM reads a bounded portion of that one response. It reports `web_exposed_phpinfo` only when the response contains real phpinfo output: the `PHP Version` banner in a dump-sized body. Stub responses are not findings.

#### Sample SQL files

A plain SQL file is reported as the lower-severity `web_exposed_sample_sql` warning when both of these hold:

- Its name is sample/schema-specific.
- It sits under framework/vendor scaffolding: `examples/`, `docs/`, `vendor/`, or an unpacked `*-main/` or `*-master/` directory.

Archived, renamed, customer-named, and other ambiguous dumps stay Critical.

#### Virtual patches for exposed files

Optionally, `auto_response.virtual_patch_exposed_files` writes reversible `.htaccess` `Require all denied` rules for confirmed exposures. It takes one of three values: `off`/`manual`/`auto`.

| Value | What CSM does |
|-------|---------------|
| `off` | Alerts only. |
| `manual` | Applies confirmed findings when you run `csm virtual-patch --apply`. |
| `auto` | Applies every confirmed class except warning-only sample SQL, and honors `dry_run`. |

- A version-control directory is patched by denying the whole directory.
- Recognized backup storage directories are denied as a unit, so regenerated archives stay blocked.
- Each change records a rollback entry. Restore refuses to overwrite a later customer edit.

#### When the exposed-file scan runs

The exposed-file scan runs in the deep tier on its own interval, because it confirms each candidate with a live request to the site and not by reading the file.

- A cycle that skips the scan on that interval leaves its existing findings in place.
- The interval starts only after a complete exposure scan. An incomplete attempt can retry on the next cycle, whether or not the realtime monitor is active.
- A deleted document root does not make the exposure scan incomplete, even if the panel still lists its domain.
- A missing root reached through a symbolic link, and a subdirectory that disappears during the walk, keep earlier findings until a later scan completes.

#### Re-checking an exposure finding

Findings in this family can be re-checked. The version-triggered startup sweep also re-checks existing findings after verifier changes.

A finding clears only after all of these are true:

- A complete vhost map provides an unambiguous current serving address.
- Both origin protocols answer there.
- The shared detection rule does not confirm an exposure any more. A phpinfo re-check repeats the bounded body confirmation too.

A missing local file alone is not enough. The finding stays open in these cases:

- The domain has migrated to another host. The re-check never falls back to DNS, so it does not clear the finding on a stranger's answer.
- The routing data is incomplete.
- The probe is unreachable or half-answered.

[Zip archives in the exposed-file scan](#zip-archives-in-the-exposed-file-scan) explains how CSM classifies a zip whose name does not say "backup".

### Hidden temporary files

The filesystem check reports a hidden regular file in the shared temporary directories when it has any of these:

- executable permissions
- ELF magic
- a leading shebang, long PHP opening tag, or short echo tag

Aliases of the same inode produce one finding. Distinct files remain separate even when their names match. Failed content reads leave the filesystem scan incomplete and preserve earlier alerts.

An inert staged blob without these signals is outside this heuristic. Nothing else is guaranteed to detect it before it is made executable or interpreted: signature and runtime detection depend on recognizable content and activity. Changing its permissions to executable makes it eligible for the next filesystem scan. This check does not establish that every unreported temporary file is safe.

## PHP Remote-Source Taint Analysis

CSM includes a PHP analyzer that looks for code that fetches content from a remote server and then executes it, even when the fetch and the execution happen in different functions. It reports `php_remote_taint`.

Regular expressions cannot express this flow. Matching it means binding the value a fetch returns to the value handed to execution, which is beyond what YAML pattern rules or YARA-X can do.

The analyzer runs as part of the scheduled deep-content scan, alongside the YARA and JavaScript consumers. To turn it off, add `php_taint_deep` (or `php_remote_taint`) to `disabled_checks`.

### What the analyzer tracks

The analyzer parses PHP source. It tracks whether a value returned by a remote-fetching call reaches a code-execution construct: `eval`, `include`, `include_once`, `require`, `require_once`, `create_function`, or `assert` given a string argument.

It follows the value through:

- variable assignment
- string concatenation
- decoding calls
- function and method boundaries
- a `file_put_contents` write into an `include` of the same path expression

### Remote sources

| Call | When it is a remote source |
|------|----------------------------|
| `curl_exec`, `curl_multi_getcontent`, `wp_remote_get`, `wp_remote_retrieve_body`, `fsockopen` | Always, whatever the argument. |
| `file_get_contents`, `fopen` | Only when the argument carries an HTTP, HTTPS, FTP, FTPS, `php://input`, or `data://` scheme. |

`file_get_contents` and `fopen` are dual-use. Only these two calls have their argument inspected. A call whose argument is clearly local is a local read. A call whose argument cannot be resolved either way is reported as a Warning (see [Severity](#severity)).

Not every `php://` stream counts as remote:

- `php://input` is request-controlled and is treated as a source.
- `php://memory`, `php://temp`, and a local `php://filter` resource are not sources.
- A filter that wraps a remote resource still carries its nested remote scheme and is classified by it.

A URL used directly as a sink's own argument, with no acquiring call in between, is out of scope. An example is `include 'http://evil/x.php'`. The pre-filter requires a source keyword before it attempts parsing, and a bare remote include has none. Such a file is reported `not_candidate`, not analyzed.

### Severity

A finding's severity follows how firmly the source was shown to be remote.

| Evidence | Severity |
|----------|----------|
| A decoder-confirmed remote fetch reaches execution | Critical |
| The fetch carries a remote URL | High |
| A dual-use call whose argument could not be resolved either way | Warning, for review |

When one file contains several flows, its strongest flow sets the severity. Legitimate template compilers and cache layers land in the Warning group, so it stays visible without paging anyone.

### Reading a flow

Each flow in a finding's details reads `source -> sink (confidence, basis)`. Examples are `curl_exec -> eval (high, always-remote)` and `file_get_contents -> include (low, unresolved)`.

The basis says how the source was identified:

| Basis | Meaning |
|-------|---------|
| `always-remote` | The call can only read over the network. |
| `literal` | The argument text carries a remote scheme. |
| `decoded` | The scheme appears only after escape or builtin decoding. |
| `request` | A requester can supply the start of the path. |
| `call-argument` | A call site in the same file passes the remote argument. |
| `unresolved` | The analyzer could not decide whether the argument is local or remote. |

The basis describes the strongest proof that reaches the sink. That proof can come from a different source call than the one the flow names. Some basis values appear only in later versions.

### Finding identity

A finding's identity is its file, its severity and the source and sink pairs of its reported flows.

- A new version that changes only the details wording or the basis does not show a dismissed finding again.
- Any change in those flows or severity, a new file, or a change to the file's content does show it again.
- When evidence is capped, basis ranking does not change which equal-confidence flows are retained.

### Files the analyzer could not examine

Only two outcomes mean a file was actually examined:

| Outcome | Meaning |
|---------|---------|
| **analyzed** | Parsing and the data-flow pass both completed. |
| **not candidate** | A fast pre-check proved the file cannot contain a reportable flow, without needing to parse it. |

Every other outcome is a coverage gap, not a clean result: oversize, a parse failure, a parser recovery that produced only a partial tree, an internal resource limit, cancellation, or an internal error. Never read a gap as "nothing to see here."

Coverage the scan could not reach is reported as `php_taint_scan_incomplete`. It names how many files were affected and why:

- A per-file status, such as a timeout or a worker failure.
- A location the walk could not read at all, where the affected files cannot even be listed.

Panics and timeouts are reported in a separate aggregate, so hard analyzer failures remain visible beside routine coverage limits. A file that had a finding and later becomes unexaminable keeps its previous finding.

### The analyzer runs in a separate process

A single file can put the underlying PHP parser into a state it never returns from, and no in-process deadline can interrupt that. So analysis happens in a supervised child process. CSM kills the child outright when a file exceeds its deadline, reports that file as reduced coverage, and continues the scan.

- Repeated failures are rate-limited, so no single account can consume the scan budget.
- The analyzer recovers without operator action.
- A file that cannot be examined is reported as unexamined, never as clean. That includes the case where no worker is available.

One check runs in the daemon itself, because it needs no parser: the byte check that decides whether a file could hold such a flow at all. A file without a PHP open tag, a code-execution construct and a remote-fetching call is ruled out there and never reaches the worker. Cancellation during this byte check is still reported as unexamined.

### PHP version support

The parser supports PHP syntax up to version 8.1. A file written against a newer PHP version may use constructs the parser does not recognize. Parsing then recovers what it can, but the result is incomplete. CSM reports the file as reduced coverage (a partial parse), not as analyzed, so an incomplete view is never presented as a complete one.

[Details](#details) covers two more rules: [oversize files](#oversize-files-in-the-php-and-javascript-analyzers) and [reduced precision](#reduced-precision-in-php-taint-analysis).

## WordPress

This family covers WordPress and the database scans for the other supported CMSes.

| Check | Description |
|-------|-------------|
| `wp_core` | Core file integrity via official WordPress.org checksums. See [Core integrity and plugin inventory](#core-integrity-and-plugin-inventory). |
| `wp_plugin_inventory` | Reports persistent plugin inventory failures as `wp_plugin_inventory_unverified`. Shares the existing refresh and interval with the outdated and vulnerable plugin checks. |
| `nulled_plugins` | Cracked/nulled plugin detection |
| `outdated_plugins` | Plugins behind the latest release, graded by version gap |
| `vulnerable_plugins` | Installed plugins whose version matches a curated known-vulnerable feed (CISA-KEV + confirmed in-the-wild CVEs). Alert-only. See [Vulnerable plugins](#vulnerable-plugins). |
| `vulnerable_timthumb` | Bundled TimThumb (`timthumb.php` / `thumb.php`) image-resizer scripts. Alert-only. See [TimThumb](#timthumb). |
| `db_content` | Database injection, siteurl hijacking, rogue admins, spam and other injected content in WordPress databases. See [WordPress database content](#wordpress-database-content). |
| `db_content_joomla` | Joomla database content scanning. See [Other CMS database scans](#other-cms-database-scans). |
| `db_content_drupal` | Drupal 8+ database content scanning. Drupal 7 not yet covered. |
| `db_content_magento` | Magento 1.x and 2.x database content scanning. |
| `db_content_opencart` | OpenCart database content scanning. |
| `db_content_prestashop` | PrestaShop database content scanning. See [PrestaShop](#prestashop). |
| `db_objects` | MySQL persistence mechanisms: triggers, events, stored procedures, stored functions. See [Database objects](#database-objects). |
| `admin_overlap` | WordPress administrator email overlap across cPanel accounts. Reports when the same admin email appears on the configured number of accounts, with reviewed emails and domains suppressible in `detection`. |
| `credential_reuse` | WordPress administrator password-hash reuse across cPanel accounts. Groups identical hashes with an in-memory fingerprint and reports only the affected accounts and count. |
| `supply_chain` | Composer and npm lockfile advisory matching against the local advisory database. Silent when no advisory file is present. |

### Core integrity and plugin inventory

`wp_core` compares core files with the official WordPress.org checksums.

- A command timeout does not mark files as verified. A timed-out re-check stays unresolved, and so does any incomplete check.
- A core file proven to differ from the release only in line endings is not reported. An install with no other difference counts as verified.
- Standalone PHP deprecation notices do not block this comparison. PHP warnings and ambiguous output still do.
- For any flagged file not proven to differ only in line endings, the daemon log says why at Info level, without copying command output.

#### When verification keeps failing

Core verification and plugin inventory report persistent failures separately from malware or integrity findings. The findings are `wp_core_unverified` and `wp_plugin_inventory_unverified`.

1. A failed attempt first appears in status.
2. Repeated failed attempts in distinct scan cycles raise a Warning. It names the installation, the last attempt and a bounded reason category.

A missing wp-cli or an unreachable checksum service stops every installation on the host at once. So when one reason covers more installations than the per-cause limit, a host scan collapses the warnings into a single finding. That finding names the reason, the total and a sample of the paths.

- The limit applies across accounts, for each kind of verification and cause.
- Account scans keep installation-specific warnings.
- The collapsed host finding is attributed to an account only when every affected installation is in that account. Sampled paths do not determine account attribution.
- Raw wp-cli output is never stored in this history.
- These warnings do not enter incidents or automatic remediation.
- The history survives restarts. A successful check clears its warning when that scan completes.

#### Checking verification coverage

`csm status`, `csm status --json` and `/api/v1/status` report the last observed coverage for core verification and plugin inventory. These counts describe previous attempts, not a fresh scan of every site. See [verification status](api.md#wordpress-verification-coverage).

Plugin coverage uses `thresholds.plugin_check_interval_min`. `disabled_checks` controls these scheduled checks. [WordPress verification attempts](#wordpress-verification-attempts) has the exact rules for what counts as an attempt.

### Vulnerable plugins

`vulnerable_plugins` reports installed plugins whose version matches a curated known-vulnerable feed (CISA-KEV + confirmed in-the-wild CVEs). It is alert-only: it never disables a plugin.

- It fires only from a fresh shared inventory, when a parseable version is inside the affected range. Patched, stale, and unparseable versions stay silent.
- Matched versions are High or Critical regardless of version gap. That includes inactive plugins, because their files remain reachable.
- `detection.vulnerable_plugin_scanning` turns the check on or off.
- `detection.vulnerable_plugin_allow` accepts one reviewed build, written as `slug@version` (case-insensitive).

#### Plugins without request filtering

For an active install, CSM marks the finding unprotected and raises it to Critical in either of these cases:

- The host engine is `Off` or `DetectionOnly`.
- The account or vhost scope is disabled.

In both cases no request filtering applies and no modsec audit record is written.

- When CSM ships a virtual patch for that CVE (`virtual_patch` in the feed), the alert says that patch cannot run. Otherwise it claims only the filtering gap.
- An inactive plugin is never marked unprotected and is not raised to Critical for this reason. Its files are why it is reported, but WordPress does not load the vulnerable code path, so a missing filter says nothing about reachability.
- An addon domain is linked only to its exact cPanel-associated subdomain. Unrelated parked, main, and addon sites that happen to share a document root do not inherit one another's disabled flags.
- Off cPanel, CSM deploys no virtual patches and no per-vhost ModSecurity state exists. Findings are left as the detector graded them.

### TimThumb

`vulnerable_timthumb` reports bundled TimThumb (`timthumb.php` / `thumb.php`) image-resizer scripts. TimThumb is an abandoned library whose remote-code-execution bug (CVE-2011-4106) is a recurring WordPress entry point.

CSM confirms a file by TimThumb's own constants, not just its filename, so generic thumbnail helpers are never flagged.

| Copy | Result |
|------|--------|
| A version below the last patch (`2.8.14`), an unparseable version, or an enabled WebShot / external-fetch feature | High |
| A patched-but-deprecated copy | Warning, to remove |
| The final release with external fetching and WebShot switched off | Suppressed |

The final release is suppressed only when `ALLOW_EXTERNAL`, `ALLOW_ALL_EXTERNAL_SITES`, and `WEBSHOT_ENABLED` are defined as false in executable PHP and none is also defined as true.

The check is alert-only. CSM never auto-quarantines TimThumb, since deleting it would break the theme.

### WordPress database content

`db_content` scans WordPress databases for database injection, siteurl hijacking, rogue admins and spam. It also raises the named findings below.

| Finding | What it reports |
|---------|-----------------|
| `db_options_new_external_script` | An external script loader in an option, on an ordinary HTTPS host that carries no attacker marker. Warning. |
| `db_options_plugin_notice_injection` | Markup that executes inside a plugin status option that WordPress renders as a dashboard notice. Critical. |
| `db_post_volume_burst` | A sudden publishing flood measured against the site's own history. Alert-only. |
| `db_spam_taxonomy` | Spam categories, tags and other taxonomy terms left behind when spam posts are removed. |
| `db_stored_code_execution` | PHP-capable snippets stored in the database by WPCode. |
| `db_stored_cloak_logic` | Stored snippets that both defeat request caching and inspect the user agent for a search or SEO crawler. |
| `db_hidden_link_injection` | Outbound links wrapped in a container the page hides from readers. |
| `db_hostname_keyed_option` | An autoloaded option named by a 32-character hex digest whose value base64-decodes to one complete PHP-serialized array. |
| `db_doorway_sitemap_routes` | Rewrite rules that pair an exact `sitemap<N>.xml` route with `feed=xmlsitemap<N>` in the same rule. |
| `db_phantom_post_author` | Published posts attributed to a user that does not exist. |
| `db_siteurl_foreign_host` | A served site whose address names a domain absent from the account's panel domains. High. |
| `db_content_scan_incomplete` | What the scan could not fully inspect. |

#### Where CSM looks for WordPress installs

CSM covers direct WordPress installs in three places:

- every document root the panel serves
- every addon-domain directory in an account home
- one directory below a document root

So a root the panel has stopped serving is still examined. Every finding states whether it came from a served or an unserved root. Served roots are reachable now. Unserved roots hold a live database that publishes again as soon as a domain is pointed at them. When the panel's domain map could not be read, CSM omits the statement entirely and does not guess.

CSM does not cover account backup, cache, staging and metadata directories. Discovery is not recursive: installs deeper than one directory below a document root are not discovered.

The `db_objects`, `admin_overlap`, `credential_reuse`, `wp_core` and plugin checks find installs the same way, and so do their fixers and re-checks. A finding raised here can therefore always be located again by the code that resolves it.

#### Multisite

The scan is multisite-aware. When `wp-config.php` declares `define('MULTISITE', true)`, CSM scans up to 100 active secondary blogs alongside the unprefixed main-site tables. The blog tables are `wp_<N>_options` / `wp_<N>_posts`, for blog IDs from `wp_blogs`.

For each blog, CSM scans its PHP-capable WPCode snippets and taxonomy, and checks its posts against the network-wide users table. Larger networks emit `db_content_scan_incomplete` and retain prior findings.

#### External scripts in options

An external script loader on an ordinary HTTPS host that carries no attacker marker is reported once, as a Warning `db_options_new_external_script`. CSM reports it the first time that host appears in an option after the site's first scan.

A value WordPress stored as JSON has every slash escaped. CSM therefore normalizes script URLs before it extracts a host, in options, in posts, and in page-builder content.

#### Plugin notice options

WordPress renders some plugin status options as dashboard notices. CSM reads two of them by name: LiteSpeed Cache's CDN setup summary and its stored message list. When one carries markup that executes, CSM reports it Critical as `db_options_plugin_notice_injection`.

Those rows hold plugin state and never site content. So neither host reputation nor the first-seen baseline applies, and a payload stored before the site's first scan is still reported.

- CSM reads the named notice rows without a script-only SQL filter.
- It inspects complete values up to 64 KiB. Oversized or malformed query rows mark the scan incomplete and retain prior findings.
- Notice findings are alert-only. This check does not rewrite stored JSON and serialized data.
- If another finding triggers option cleanup, cleanup refuses to write while any executable notice markup remains, even when its host has no reputation marker.

#### Publishing floods, spam terms and phantom authors

`db_post_volume_burst` fires only on sites older than 400 days, with at least 50 recent posts and more than 5x everything published before. A genuine content migration looks the same, so the finding is alert-only.

For `db_spam_taxonomy`, a term named after a URL is High. Spam vocabulary alone is Warning.

`db_phantom_post_author` is Critical at 100 posts or more and Warning below. Small orphan groups can result from direct SQL user deletion. Large groups can identify doorway content whose invented author IDs are hidden from dashboard queries.

#### Stored code snippets

Stored code is invisible to filesystem scanning, so CSM reads the snippets that WPCode keeps in the database.

| Finding | Severity |
|---------|----------|
| `db_stored_code_execution` | Critical when the snippet is published and therefore running. Lower when it is a draft or trashed. |
| `db_stored_cloak_logic` | High when published and Warning otherwise. |

For `db_stored_cloak_logic`, a snippet defeats request caching with any of these: true `DONOTCACHEPAGE`, false `WP_CACHE`, WordPress no-cache headers, or LiteSpeed's no-cache response header. CSM recognizes direct, concatenated, and ROT13 crawler names.

A snippet that already matched a malware signature carries the cloak as a bounded note. It does not raise a second finding.

#### Hidden links

`db_hidden_link_injection` depends on how the container is hidden.

| How the container is hidden | Result |
|-----------------------------|--------|
| Off-canvas: a large negative `left`/`top`/`text-indent` | High on its own. |
| `display:none`, `visibility:hidden` or fully transparent opacity | Reported only with corroboration: a second linked domain in the same container, or spam vocabulary. Themes legitimately hide panels that link out. |

- Links back to the site's own registrable domain are ignored. Both the WordPress home and site addresses count as local.
- Corroboration counts registrable domains within one hidden container, not hostnames across a whole row. Multiple subdomains of one linked domain count as one target.
- The scan is skipped when `siteurl`/`home` cannot be read, since every absolute link would then look external.
- Markup is tokenized, not parsed into a tree. Nesting the injection past a tree parser's open-element limit does not hide it.

#### Hostname-keyed options and doorway sitemap routes

For `db_hostname_keyed_option`, kits key the digest to the site's own hostname so one payload serves many sites. Both halves are required, the digest name and the base64 value, because plugins do write hashed cache keys and base64 alone is ordinary.

For `db_doorway_sitemap_routes`, the matching number is what distinguishes a doorway cluster from paginated sitemaps. Sitemap plugins add numbered rewrite rules too.

Option reads are size-limited. A read that leaves out any stored bytes marks the scan incomplete, and that row does not produce a finding.

#### Site address checks

WordPress builds every asset URL from the site address. CSM reports a site address when its shape cannot be one: a missing host, an invalid port, a backslash, a query string, a fragment, a script for a path, or a non-web scheme.

Invalid-address findings are alert-only. Only explicit code injection enters database auto-response.

Serving a site under a domain hosted elsewhere is ordinary and is not reported on its own. `db_siteurl_foreign_host` (High) is reported once per site when both of these hold:

- The panel is serving the root right now.
- The site address names a domain absent from that account's panel domains.

Ownership follows the panel's most-specific exact or wildcard domain mapping. A delegated subdomain therefore belongs to its own account, not to the account holding its parent.

A site that was migrated away is not served here any more. Whether the panel serves the root is therefore what separates a migrated copy, which is not reported, from a foreign address that is. An unserved root, an incomplete domain map, or a value the shape check already reports stays silent, so CSM does not say it twice.

#### How WordPress findings are told apart

WordPress content findings use the account, database server, database name, and table prefix to stay separate. Changes to the panel's document-root map do not create duplicate findings.

| Change | Result |
|--------|--------|
| A suspicious snippet that was inactive is published | A fresh alert, even when the earlier condition was baselined or dismissed. |
| An orphaned-post group grows into a Critical content farm | A fresh alert, even when the earlier condition was baselined or dismissed. |
| An ordinary count change within the same orphaned-post severity tier | The existing identity is kept. |

Hidden-link findings are tracked per account, database host, database, and table prefix.

- More affected rows or a different row order do not raise another alert for the same destinations and concealment strength.
- Off-screen concealment raises a new High even after an earlier Warning was baselined or dismissed.
- Changes to destinations outside the displayed sample also produce a new finding.
- After an upgrade from a version that identified hidden-link findings differently, existing hidden-link findings can appear once more. Previous dismissals do not transfer to them.

#### What the scan could not inspect

The WordPress database scan reports what it could not fully inspect as `db_content_scan_incomplete`. The finding counts affected installs against the number discovered. It names one bounded example config path per reason:

- `unreadable_config`
- `missing_credentials`
- `unresolved_table_prefix`
- `query_failed`
- `incomplete_content`

[WordPress database scan coverage](#wordpress-database-scan-coverage) has the counting rules and explains which findings an incomplete scan keeps.

### Other CMS database scans

The Joomla, Drupal, Magento, OpenCart and PrestaShop scans work the same way. Each finds installs by a marker file, reads the database login from the CMS configuration, and scans settings, content and administrator rows.

These rules apply to all five:

- Every query is capped at 200 rows and runs under the scan deadline.
- Installs under addon-domain document roots are discovered too.
- Administrator rows are baselined on the first pass. See [Administrator baselines](#administrator-baselines).

#### How installs are found

| CMS | Install marker | Credentials |
|-----|----------------|-------------|
| Joomla | `configuration.php` containing `class JConfig` | Parsed from `public $...;` assignments. |
| Drupal 8+ | `sites/default/settings.php` plus the `core/lib/Drupal.php` marker | Parsed from the `$databases` array. |
| Magento 1.x and 2.x | `app/etc/env.php` (M2, preferred) or `app/etc/local.xml` (M1) | Parsed via `encoding/xml` for M1 (CDATA-aware) or field-level regex for M2. |
| OpenCart | The `config.php` + `admin/config.php` pair, both containing `define('DB_DRIVER'` | Parsed from `DB_HOSTNAME` / `DB_USERNAME` / `DB_PASSWORD` / `DB_DATABASE` / `DB_PREFIX` defines. |
| PrestaShop | `config/defines.inc.php` containing `_PS_ROOT_DIR_` | See [PrestaShop](#prestashop). |

#### What is scanned

| CMS | Tables |
|-----|--------|
| Joomla | `<prefix>extensions` params, `<prefix>content` article bodies, and `<prefix>users` joined with `<prefix>user_usergroup_map` for Super User detection (group_id=8). |
| Drupal | `config`, `node_revision__body`, and `users_field_data` joined with `user__roles` (administrator role). |
| Magento | `core_config_data`, `catalog_product_entity_text`, `cms_block`, `cms_page`, and `admin_user` (with the configured `db.prefix`). |
| OpenCart | `<prefix>setting` (`config_url` / `config_ssl` are canonical hijack targets), `<prefix>product_description`, `<prefix>information_description`, and `<prefix>user` (admin/staff). |
| PrestaShop | See [PrestaShop](#prestashop). |

#### Findings

| CMS | Findings |
|-----|----------|
| Joomla | `joomla_extensions_injection`, `joomla_content_injection`, `joomla_admin_injection` |
| Drupal | `drupal_settings_injection`, `drupal_content_injection`, `drupal_admin_injection` |
| Magento | `magento_settings_injection`, `magento_content_injection`, `magento_admin_injection` |
| OpenCart | `opencart_settings_injection`, `opencart_content_injection`, `opencart_admin_injection` |
| PrestaShop | `prestashop_settings_injection`, `prestashop_content_injection`, `prestashop_admin_injection` |

#### Administrator baselines

On the first pass CSM records the administrators that exist. Only an administrator that appears later is reported, once, as High. Later additions produce one High finding per new administrator. Finding details identify the affected database and prefix.

Baselines for Joomla, Drupal, Magento, OpenCart, and PrestaShop are scoped to the hosting account, CMS, database host, database name, and table prefix.

- Two sites under one account keep separate baselines when they use different databases or prefixes.
- Paths that share the same database and prefix share the same administrator set.
- Upgrading from account-wide baselines starts a fresh baseline for each installation on its first complete administrator query.
- Administrator baselines and recorded IDs change only after a complete result. A successful empty administrator result also establishes a baseline.
- New IDs in a partial result can still be reported against an existing baseline.

#### Accounts and copies that are skipped

The Joomla, Drupal, Magento, OpenCart, and PrestaShop scans skip suspended accounts. A suspended account's database user is locked, so scanning it would only leave the check incomplete.

- The skip happens before CSM reads the configuration or applies the account scan file limit.
- Both Magento configuration layouts use this filter.
- Only installs with a resolved owner and a cPanel suspension marker are excluded. Unowned paths remain eligible.
- Active accounts still scan when others are suspended.

PrestaShop also skips staging, backup and cache copies: folders named `staging`, `backup`, `backups`, `cache` and `.trash`, matched without regard to case.

#### PrestaShop

Where the credentials come from depends on the version. No other configuration value is read.

| PrestaShop version | Credentials |
|--------------------|-------------|
| 1.7.4 and later, 8 and 9 | The six `database_*` entries of `app/config/parameters.php`. |
| 1.6 | The `config/settings.inc.php` defines, used when neither `parameters.php` nor `parameters.yml` exists. |
| 1.7.0 to 1.7.3 | These shops keep their live settings in `parameters.yml`. The scan stays incomplete. |

The scan covers every language and shop, and raises one finding per setting, page, product or category. It reads:

- `<prefix>configuration` and `<prefix>configuration_lang` values
- `<prefix>cms_lang` content
- `<prefix>product_lang` descriptions and short descriptions
- `<prefix>category_lang` descriptions

Setting values are never shown, because the mail password is stored among them.

Back-office employees are baselined on the first pass.

| Change after the baseline | Finding |
|---------------------------|---------|
| An employee appears | Reported once as High. |
| A new employee has the SuperAdmin profile, or an existing employee is moved to it | Reported once as Critical, instead of the High finding. |

An employee demoted and later promoted again is reported again.

PrestaShop scans employees first, so settings or content limits do not prevent employee baselines or SuperAdmin alerts. When the employee query returns more rows than the limit, coverage stays incomplete and the recorded employee baseline and SuperAdmin set are left unchanged. Settings and content queries still run within their own row limits and the scan deadline.

#### Re-checking a CMS finding

A CMS re-check looks at every install of the account in the layouts the scanner discovers: the account's `public_html` and each folder directly under its home. It uses each install's own database login and endpoint, including custom ports and sockets.

| Finding | Where it is re-checked |
|---------|------------------------|
| Administrator findings and every PrestaShop finding | They record their database host, database name and table prefix, and are re-checked only in that install. |
| Joomla, Drupal, Magento, and OpenCart settings and content findings | They do not record an install, so the re-check looks at every install of that CMS on the account. |

| Finding | When it resolves |
|---------|------------------|
| Joomla, Drupal, Magento, and OpenCart settings and content | Only when the row is clean or absent in every install of that CMS on the account. |
| PrestaShop settings and content | Only when every language, shop and scanned column is clean or absent. |
| New employee | Only when the employee is deleted. |
| SuperAdmin | When the employee is deleted, and also after demotion. |

A finding stays unchecked in these cases:

- An install is unreadable, or the recorded database is one that no install uses.
- The configuration cannot be read, or a query fails.
- Listing the home directory or discovering installs fails.
- The home folder holds a symlink loop, or a permission or I/O error occurs.

Links in the home folder that point nowhere or to regular files are ignored. Linked folders naming the same database are checked once.

Re-checks inspect every relevant database even after finding an injection, so a later query failure still leaves the finding unchecked.

[CMS database scan limits](#cms-database-scan-limits) covers configuration reads, row limits and query errors.

### Database objects

`db_objects` reports MySQL persistence mechanisms: triggers, events, stored procedures and stored functions.

| Case | Severity |
|------|----------|
| The body matches known-malware patterns (`sys_`+`exec`, `INTO OUTFILE`, `LOAD_FILE`, etc.) | Critical |
| An object exists at all (vanilla CMSes ship none) | Warning |

- `detection.db_object_scanning` turns the check on or off.
- `detection.db_object_allowlist` suppresses Warnings.
- `csm db-clean --drop-object` drops an object manually.

## CMS Scanner Support Policy

New CMS scanner work targets upstream-supported major versions. EOL versions are best-effort when the existing scanner covers them through the same low-risk layout or schema. Adding a new EOL-only scanner needs operator fleet data and an explicit security reason.

Current scanner scope:

- WordPress single-site and multisite.
- Joomla installs using the common `configuration.php` / `JConfig` layout and standard content/user tables used by supported Joomla releases.
- Drupal 8 and newer. Drupal 7 is not a planned support target.
- Magento 1 and 2.
- OpenCart installs using the standard storefront and admin config pair.
- PrestaShop 8 and 9; 1.7 and 1.6 best-effort through the same schema.

Database object scanning (`db_objects`) discovers WordPress installs only.

The supported kinds are declared once in `internal/cms`. Tests check three things against that table:

- The database scanners and the PHP taint analyzer's knowledge of each CMS's bootstrap path constants are tested against it.
- Every typed CMS kind constant, including local declarations and aliases, must have exactly one descriptor. Membership drift fails the tests.
- The clean-corpus manifest is validated against it: every supported CMS is either pinned as a source or listed as pending with a reason.

Support does not by itself mean a CMS has clean-corpus false-positive evidence (see [the clean corpus](clean-corpus.md)).

## Phishing & Malware

| Check | Description |
|-------|-------------|
| `phishing` | 8-layer phishing detection (kit directories, credential harvesting). See [Phishing scans](#phishing-scans). |
| `email_content` | Outbound email body scanning for credentials and suspicious URLs. See [Outbound email content](#outbound-email-content). |

### Phishing scans

Suspected kit directories are reported for review. `auto_response.quarantine_files` applies only to eligible page findings.

The `phishing` entry in `disabled_checks` controls the check, kit archive scanning included.

#### Kit archives

CSM judges a kit archive from its file list. An isolated worker reads the list without decompression.

- If an archive's file list cannot be read or is malformed, the check is left incomplete.
- If the ZIP worker is unavailable, the check stays incomplete. ZIP parsing never falls back into the daemon.

An archive that causes two worker failures within 24 hours is skipped on later scans. CSM raises a `phishing_kit_archive_unscannable` warning that names its path and SHA-256. That skip alone does not leave the check incomplete.

- The failure record expires 24 hours after its last failure. It is held in memory, and a daemon restart clears it.
- Changed content is eligible for scanning. A file rewritten while the worker runs cannot acquire a failure for its replacement contents.
- Malformed listings, canceled scans, and a worker that CSM refuses to start after repeated failures leave the check incomplete without adding failures against the archive.
- While a failure record exists, scans hash each candidate archive before requesting its list. Once all failure records expire, the hashing stops.

#### Brand evidence in titles

Phishing title analysis ignores a brand that appears only inside an email address, even when the page also carries a login form. A blog author archive named after its author is one example.

Elsewhere in the title, password capture or a login title lets a brand glued to other words still count. Malformed address-like text does not hide brand evidence.

Directory brand evidence uses the same title rules as page analysis and checks visible body content. A brand that appears only inside an email address in the title, or only in hidden markup, does not establish impersonation.

#### Which paths are read

- Phishing directory analysis honors `suppressions.ignore_paths` for the pages it reads, just as page analysis does. Explicit audits can bypass those exclusions.
- The phishing and group-writable PHP scans include dependency and source-control folders within their depth budgets.
- Neither scan recurses through directory symlinks.
- Phishing content reads also refuse file symlinks and special files, and a special file such as a FIFO cannot make the scan hang. This holds when a regular file is replaced during a scan.
- The PHP permissions check uses regular-file permissions, so a symlink's write bits do not produce a finding.

### Outbound email content

`email_content` scans only mail submitted on this server. Unauthenticated mail arriving from other servers is not scanned.

- Scanning covers any authenticated SMTP client, including logins Exim records without a mailbox, and local processes.
- Messages are found in both flat and split Exim spool layouts.
- Oversized headers are checked from a bounded prefix. Long padding lines do not discard readable evidence or stop body checks.
- Quarantine and re-check act only on the message ID the finding names. The envelope sender is shown in the finding details and mailbox field.

## Files Planted Alongside Malware

A webshell kit is usually dropped in one session: a loader no rule matches, an encrypted payload, a binary dropper, an access file. Removing only the member a scanner recognized leaves the rest in place. When CSM proves one file malicious, it looks at the other files in that file's directory and reports the ones planted with it. This page calls that a sweep.

Files are matched by change time, not modification time. Kits backdate modification times, but the kernel sets the change time on every write and an account cannot forge it.

### What triggers a sweep

| Event | Sweep |
|-------|-------|
| A Critical finding from a content scanner, a YARA or signature rule, or a known webshell or backdoor name | Yes. The source can be the realtime monitor or a scheduled scan, including the startup scan. |
| A successful quarantine or cleaning through the daemon, including manual dashboard actions and access-file cleanup | Yes. The metadata comes from before the move or rewrite. |
| A refused action | No. |

An account scan sweeps for the detections in its own results and includes the outcome in its report.

### Which files a sweep considers

- A sweep covers the detected file's own directory, not its subdirectories.
- It never follows or reads symlinks and special files.
- Content is read through the directory the sweep opened and from the file version it selected. A file or directory swapped in during the sweep is not read in its place.
- Only files owned by the detected file's owner count, because an account can only create files it owns.
- The window runs from ten minutes before to ten minutes after the detected file's change time. Only files changed inside it are considered.

A file caught as it is written may be the first of its kit to land. Its sweep waits until the window has closed.

### How the files are scanned

A first pass reads metadata only. Then two groups get a full content scan, regardless of scan caches: the files in the window, and the directory's `.htaccess` whatever its age. The content scan uses YARA, the PHP content heuristics, PHP taint analysis and the `.htaccess` audit.

- A match is an ordinary finding and follows the normal response policy.
- Account scans retain their requested file-size limit.
- Failed PHP analysis is reported as incomplete, not as a clean result.
- A huge directory costs one metadata read per entry. Only files written in the window and `.htaccess` are opened.

### What the finding lists

Files in the window that nothing matched are listed in one High `malware_companion_files` finding. A file is listed when it is PHP, an executable, an archive, a file without an extension, or `.htaccess`. Each entry shows size, change time and modification time.

A modification time more than a day older than the change time is marked as possible backdating. Unpacking an archive also keeps old modification times, so treat the mark as a hint.

CSM never quarantines these files on its own. Review each one first.

### When a sweep fails or cannot help

| Case | Result |
|------|--------|
| The sweep times out | A `check_timeout` warning. |
| A directory or content scan fails | `malware_companion_scan_incomplete`. |
| A bulk ownership or permission change, or an account restore, touched the directory | Every touched file gets a new change time. A detection there lists every file of a reported kind from the same operation. |
| The daemon restarts while a sweep waits for its window | Waiting sweeps are held in memory, and a restart drops them. |
| A standalone CLI cleanup command did the action | The daemon worker does not run. Use an account scan to inspect companions when the action runs outside the daemon. |

[Companion sweep limits](#companion-sweep-limits) lists how often a directory is swept and how sweeps share scan capacity.

## System Integrity

| Check | Description |
|-------|-------------|
| `rpm_integrity` | System binary verification via rpm -V |
| `open_basedir` | open_basedir restriction validation |
| `php_config_changes` | Security-weakening `.user.ini` and `php.ini` files under account web roots |

A package integrity re-check keeps the finding while the package verifier still reports a modification for the flagged file. Changing the file's executable mode or removing the file does not by itself resolve that finding.

## DNS & SSL

| Check | Description |
|-------|-------------|
| `dns_zones` | Security-sensitive DNS zone changes (delegation, mail, apex, and wildcard records) |
| `ssl_certs` | SSL certificate issuance (subdomain takeover) |
| `waf_status` | WAF mode, staleness, bypass detection. See [WAF rule staleness](#waf-rule-staleness). |

### WAF rule staleness

| Platform | How `waf_status` judges staleness |
|----------|-----------------------------------|
| cPanel | It follows vendor configuration files that WHM reports as active and ignores retired trees that remain on disk. The warning means at least one loaded vendor has not refreshed in over a month. |
| Other platforms | It keeps the conservative oldest-artifact check, so an unused fresh tree cannot hide stale loaded rules. |

## Email Security

| Check | Description |
|-------|-------------|
| `email_weak_password` | Email accounts with weak passwords; in-process verification with [supported hash formats and cost limits](email-av.md#email-password-audit) |
| `email_password_audit_incomplete` | Password verification was interrupted or encountered a hash outside the supported audit formats or limits |
| `email_forwarder_audit` | Forwarders redirecting to external addresses, piping mail to a command, or discarding it. See [Forwarders](#forwarders). |
| `email_mail_filters` | Exim mail filters and dovecot/Roundcube Sieve scripts that forward mail externally, pipe it to a command, or blackhole all mail. See [Mail filters](#mail-filters). |

### Forwarders

`email_forwarder_audit` does not report pipes that run cPanel's autoresponder, BoxTrapper or Mailman list software. Scheduled and real-time scans interpret command quoting and escaped destination quotes using Exim's rules.

### Mail filters

`email_mail_filters` reports Exim mail filters and dovecot/Roundcube Sieve scripts that do any of these:

- copy mail to an external address while keeping a local copy
- forward externally
- pipe to a command
- blackhole all mail

Sieve is what webmail-managed rules actually execute, so both are scanned.

A forward that leaves the mailbox its own copy is what a webmail forward rule produces. Its severity depends on corroboration:

| Forward that keeps a local copy | Severity |
|---------------------------------|----------|
| On its own | Warning, for review |
| Corroborated by an independent forwarding layer on the same mailbox, by mail the mailbox never receives, or by the same destination across accounts | Critical |

Each Critical forward is also [compromise evidence](detection-realtime.md#mailbox-compromise-evidence) for its mailbox. An uncorroborated forward that keeps a copy is not.

The full audit runs on the email audit interval. The next deep scan picks up edits to a Sieve script, including the target of an active script link.

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
| `perf_wp_loopback` | WordPress self-requests sustained above once a minute |
| `perf_wp_myisam` | WordPress tables still on the MyISAM storage engine |

## Platform Support

The deep checks are the most cPanel-biased part of CSM, because they iterate account home directories and per-user public_html trees. On plain Ubuntu/AlmaLinux the account-scan based checks do not run.

### cPanel-only checks

These checks are skipped on plain Linux.

| Checks | What they read |
|--------|----------------|
| `htaccess`, `file_index`, `php_content`, `group_writable_php`, `symlink_attacks` | They iterate `/home/*/public_html/**`. |
| `wp_core`, `outdated_plugins`, `vulnerable_plugins`, `db_content`, `db_objects`, `admin_overlap`, `credential_reuse` | They find WordPress installs through the shared discovery. See the list below the table. |
| `supply_chain` | It scans `composer.lock` and `package-lock.json` under `/home/*` and `/home/*/public_html`. |
| `phishing`, `email_content` | They scan user home directories and Exim spool. |
| `dns_zones`, `ssl_certs` | They read cPanel's DNS zone store and SSL installation records. |
| `email_weak_password`, `email_forwarder_audit` | They read `/etc/valiases` and Dovecot/Courier auth databases. |
| `email_mail_filters` | It reads per-mailbox Exim filters under `/home/*/etc/<domain>/<localpart>/filter` and domain filters under `/etc/vfilters`. |
| `open_basedir` | It reads EA-PHP `php.ini` under `/opt/cpanel/ea-php*/`. |
| `php_config_changes` | It recursively scans `.user.ini` and `php.ini` below account web roots. Incomplete walks emit a coverage finding and preserve prior findings. |
| `perf_wp_config`, `perf_wp_transients`, `perf_wp_cron`, `perf_php_handler` | WordPress and PHP handler introspection via cPanel's EA-PHP layout. The WP-Cron check also uses cPanel's domain map for addon and subdomain roots. |

The shared WordPress discovery looks in these places:

- the panel document-root map
- `/home/*/public_html`
- one directory below it
- addon-domain directories in an account home

Unresolved document-root aliases retain prior findings and cached plugin inventory. CSM does not treat a partial walk as a clean result.

### Checks that run on every platform

| Checks | How they run |
|--------|--------------|
| `filesystem`, `webshells` | fanotify and file-tree scans over `/home`, `/tmp`, `/dev/shm`. |
| `rpm_integrity` | It dispatches to `rpm -V` on RHEL family or `debsums` / `dpkg --verify` on Debian family. |
| `waf_status` | It detects ModSecurity on Apache, Nginx, and LiteSpeed across all supported distros. |
| `perf_mysql_config`, `perf_redis_config`, `perf_error_logs` | They rely on standard service locations. |
| `perf_wp_myisam` | It uses shared WordPress discovery in the deep tier, including account home layouts when no panel map is available. |

### Generic web roots on plain Linux

Operators on plain Linux can point `perf_error_logs`, `perf_wp_config`, `perf_wp_transients`, and `perf_wp_cron` at generic web roots with the `account_roots` glob list (see [configuration.md](configuration.md)). The remaining account and CMS scans still assume the cPanel `/home/*/public_html` layout.

## Alert delivery

Alert email and the generic alert webhook share repeat state: one record of which findings were already sent. A successful send through either channel counts as delivered.

A finding that was not delivered remains eligible on later reports, without waiting for the daily history reminder. That covers findings held by the hourly cap, failed sends, and disabled notifications. It includes findings derived from current observations.

Baselines, dismissals and suppression rules still apply, including to the sources of cross-account summaries. The signed phpanel stream keeps its separate delivery policy.

### Findings that keep one alert identity

These findings keep one alert identity per condition and severity:

| Finding | What identifies the condition |
|---------|-------------------------------|
| SMTP probe | The source address. |
| Self-deleting dropper | The removed file, directory or document root. |
| Sensitive file write | The written file with its writer and, when the write can be tied to the file's content, that content. |
| Email AV degraded | The scanner condition. |
| Auto-block notice | The kind of notice. |

Counts, process or message IDs, ages, sizes, error text and the files sampled in a burst can change without a new alert.

Dismissing one of these findings covers its later reports until it goes unseen for 24 hours. A return after that alerts again.

### Cross-account summaries

- A cross-account summary alerts again when the affected accounts change, including after a dismissal.
- More reports for the same accounts do not repeat the summary.
- Summaries are derived per dispatch batch. Different scan tiers or realtime batches can therefore report different subsets of the affected accounts, and each subset is emailed once.

### When a finding alerts again

| Case | Result |
|------|--------|
| An undismissed finding goes 24 hours without an observation | It can alert again, even when no other batch arrived to clean up old state. |
| A finding stays on the findings page | It counts as observed, even on the runs its check skips between reports. A check that reports once a day does not email daily. |
| CSM was down for at least 24 hours | An open finding alerts once on its next report. |
| A completed scan covered the finding and does not report it any more | A later return can alert. |

Scan coverage warnings follow their own policy. See [Scan coverage alerts](#scan-coverage-alerts).

### Acknowledged findings

Keeping acknowledged findings listed does not rewrite alert state. The one exception is a dismissal of one of the [findings that keep one alert identity](#findings-that-keep-one-alert-identity): it lapses once the finding has gone unseen for 24 hours.

Other retained findings use the existing periodic save. Their delivery state survives restarts, and the displayed last-report time does not change.

## Scan coverage alerts

A coverage warning says that a scan could not examine everything. The PHP, JavaScript, YARA, host-wide WordPress database coverage, and unfinished email password verification warnings each keep one alert identity while their counts change.

Alert email and the alert webhook send each warning once. History records it again once a day unless it is acknowledged.

| Case | Result |
|------|--------|
| The owning scan returns without the condition | Its acknowledgment clears, so a later recurrence can alert again. |
| An unacknowledged condition returns | It is emailed again only if it went unreported for 24 hours. A gap that is missing from one complete scan and back in the next sends no new email. |
| An unrelated scan, throttled check, timeout, or cancellation | It does not prove recovery. |
| You disable a scanner | Its current coverage condition clears. |
| A partial scan cannot inspect some installations | Existing per-install database limit acknowledgments for them are kept. |

### JavaScript coverage gaps

JavaScript scans bound the paths retained for coverage gaps. If that list is truncated, the coverage warning says so and still counts every analysis failure.

The scan keeps all earlier JavaScript detections and can report new ones. A later complete scan can clear findings for content it has examined or that is gone.

### Analyzer and check crashes

PHP analyzer crashes and stalls are tracked by the failing file paths, contents, and failure statuses, including files outside the displayed examples. Different failing inputs can therefore alert even after an earlier failure was dismissed.

Check crash alerts ignore stack-trace churn, keep account scans separate by account, and re-arm after the same check returns successfully.

## Re-verifying Findings

A finding records what was true when it was raised. Someone else often resolves the condition behind it: an operator cleans a file, or a virtual patch denies an exposure. None of that changes CSM's own rules. So re-verification runs once per deep-scan cycle, and also when the re-check logic changes.

### Which findings a scan retires

A scan retires a finding it did not raise again only for files it actually examined. Coverage is tracked per file and scanner.

| Coverage gap | Findings that are kept |
|--------------|------------------------|
| A gap that names a file: one past the scan size limit, or one that could not be opened | That scanner's findings for the file, and nothing else. |
| A gap with no path, such as a directory the walk could not enter or a stat that may hide a subtree | Every finding the scanner owns, because the unscanned range is unknown. |

Tracking per file matters. A single oversized log that will never fit under the limit is a permanent gap, and treating it as a whole-scanner gap would freeze every finding on the host indefinitely.

- On a large server the rolling deep scan covers the files over several runs. Each run retires findings for the files it examined, up to where its time budget ran out.
- Overlapping and symlinked scan roots are walked in one path order, so an interrupted run never retires findings in a root it has not reached.
- A finding raised by an older version is not tied to its file this way. It waits for a complete scan or re-verification.

### Re-check outcomes

Each family is re-checked by running again the test that raised it. There are four outcomes:

| Outcome | When |
|---------|------|
| **Cleared** | The condition is provably gone: the file was removed, or the server has stopped serving it as an exposure. If the same detection returns later, it alerts as a new finding. |
| **Demoted to Warning** | The flagged content is gone but the file changed since detection, so the cleanup cannot be proven byte-for-byte. |
| **Restored** | A demoted finding whose replacement stops being inert returns to the severity it came from. |
| **Left alone** | Anything uncertain: an unreachable or half-answered probe, a domain that this host has stopped serving, a replacement that changed while it was being read, a file that still matches. |

A finding keeps its identity throughout. Only its severity changes.

### Demotion rules

A demoted finding is kept, because an attacker must not be able to retire one by editing the file. It stops ranking beside live threats.

Only a replacement proven inert qualifies for demotion:

- an empty file
- a comment-only PHP stub with a valid opening tag and no closing tag

A malformed opening tag can leave the file serving page content, so it does not qualify. Attribute declarations do not qualify as comment-only stubs either.

This is an allow-list on purpose. A deny-list of dangerous shapes would make every omitted include, callback or inline script a way to buy a lower severity.

Restoring exists so that a second edit into a detection gap cannot leave live content sitting at Warning.

### Re-checks and newer reports

A re-check applies its verdict only to the finding as it was when the re-check examined it. If a scan or realtime alert refreshes the same finding while a re-check is in flight, the older verdict never overwrites it.

An unconfirmed demotion also survives a scan that does not raise the finding again. That scan is weaker evidence than the verifier that reads the file.

## Details

The sections below are reference material for edge cases. You do not need them to read a finding or to run the checks.

### File index and PHP content scans

The file index:

- Failed content reads preserve prior findings for that file.
- After a large deletion, scans walk the directories again until the smaller baseline is adopted. CSM adopts a much smaller baseline only after several scans in a row find it. Cached entries therefore cannot bring removed paths back or break that run of scans.

The PHP content scan reuses a clean result only when the file's identity and timestamps still match a stable read.

- Recently changed files, files that change during inspection, and files without usable identity metadata are read again on the next visit.
- After an upgrade, older cached results are refreshed as files are visited.
- Interrupted scans retain progress.
- Periodic host scans bypass the cache.
- Explicit full-content scans always read the files they visit.

PHP execution heuristics tell executable calls apart from attribute metadata and multiline string contents:

- Literal examples do not establish callable bindings or invoke them.
- Scanning continues through code after attributes.
- String boundaries and legacy line endings preserve the executable code that follows them.

PHP and phishing checks read `${'_POST'}` and `$GLOBALS['_POST']` as `$_POST`. The same text inside a quoted string or a comment is ignored.

### .htaccess detection rules

Prepend and append targets:

- Every prepend or append target carried in a line is judged. That includes `SetEnv` values and `RewriteRule` environment flags, with variable names expanded by Apache.
- Apache quoting and flag separators are not part of the target.
- Harmless prepend settings and defensive rewrite patterns are not reported.

Handler mappings:

- A handler-abuse finding requires a complete extension argument in an active handler directive. There is one finding per directive.
- Disabling CGI suppresses CGI handler mappings only when the active options keep CGI disabled. PHP mappings remain reportable.

`htaccess_security_disabled`:

- It covers the mod_security 1.x spellings too, because LiteSpeed obeys them by default.
- Magento's stock block that turns ModSecurity off is reported and cleaned like any other.

`htaccess_rewrite_off_shield`:

- It reports rewriting switched off beside an access grant whose FilesMatch pattern can match no file name. That is the unfilled template a dropper kit writes.
- Asset folders that grant named file types stay quiet.
- Only active access grants count, including quoted and continued directives.
- Cleaning preserves unrelated bytes. It removes an enclosing rewrite module block only when the offending switch is its entire body.

A prepend of a security plugin's own file is not reported. For Really Simple Security the rule is strict:

- The target must be the absolute path of `wp-content/advanced-headers.php` beside the `.htaccess`, with no dot segments.
- A document root reached through a symbolic link counts as the same place.
- Any other target naming that file is reported wherever it points. When it is a prepend it is never cleaned automatically.

### Zip archives in the exposed-file scan

A zip whose name carries no backup wording is classified from its central directory instead. So an archive named after the site it holds is reported when it contains any of these:

- a site-root or structured CMS configuration path
- a regular Joomla configuration file at any depth whose same case-sensitive folder also holds a regular Joomla core file
- a document-root directory
- a database dump at the archive root

Plugin and theme bundles offered as ordinary downloads stay quiet.

- Readable backup evidence is retained even if later directory records are damaged.
- The complete entry list is inspected within a fixed metadata budget, without extracting or decompressing payloads.
- An archive that exceeds the budget leaves the scan incomplete. It does not silently clear an earlier finding.

### Oversize files in the PHP and JavaScript analyzers

Both analyzers are handed every readable file the walk produces, and their own pre-check rejects the rest instantly. That pre-check never runs on a file too large to send. Without another step, every large image, archive and compiled catalog on the host would count as source the scan had failed to examine.

So an oversize file is judged once more before it counts. Only a file whose leading bytes could be source of that language is reported.

| Language | How the prefix is judged |
|----------|--------------------------|
| PHP | By an opening tag anywhere in the inspected prefix, including after binary content. Binary content carrying PHP tokens can therefore remain reportable. The prefix alone cannot establish that it is inert. |
| JavaScript | JavaScript has no such marker. A prefix without NUL is admitted. One containing NUL gets a conservative lexical check, since binary characters are legal in JavaScript literals and comments. Incomplete tokens and ambiguous syntax remain reportable. |

Neither gate looks for taint source or sink keywords in the prefix. When the prefix cannot be read, the file is reported for either language, because a file the scan could not examine is exactly what the report exists to name.

### Reduced precision in PHP taint analysis

Separately from the outcome, an analyzed file can still report reduced precision. Some constructs defeat static variable identity:

- `extract()`
- `compact()`
- variable variables
- a call dispatched through a value
- an assignment target the analyzer cannot name
- a value a closure or arrow function captures from its enclosing scope

CSM records each one alongside the result. A recorded loss means tracking stopped at that point and the file may hold a flow that was not followed. It is never left implicit.

The capture case is recorded only when the captured value was itself tainted. It therefore marks a real loss, not the mere presence of a closure.

### WordPress verification attempts

What counts as an attempt:

- Cache reads do not count as attempts.
- A wp-cli refusal that explicitly identifies a non-WordPress directory is recorded as not applicable, not as an outage.
- A completed core check that finds modified or missing files retains its existing integrity findings and is counted separately.
- Only the completed checksum summary establishes a negative verification result. Partial warnings without that summary remain unverified.
- Overlapping scans preserve attempt order and failure streaks even when they finish out of order.
- New discovery alone does not discard an attempt still finishing in another scan.

Plugin coverage:

- Partial refreshes keep the existing refresh policy.
- Plugin coverage performs no refresh when both inventory consumers are disabled.

Discovery:

- Cancellation and incomplete discovery retain earlier evidence.
- Complete discovery removes installations that are not present any more, scoped to the account scanned.
- A domain the panel still lists after its directory was deleted holds no installation. It does not make discovery incomplete when the original mapped config path is also confirmed absent.
- Ambiguous symlink resolution, account boundary violations, and inspection errors keep discovery incomplete and retain earlier evidence.

### WordPress database scan coverage

These rules apply to `db_content_scan_incomplete` and to the findings an incomplete scan keeps.

#### How installs and reasons are counted

- Each install counts once. Installs sharing a failed database count as affected without retrying its queries.
- Content gaps include truncated or unusable query results.
- Example paths use ASCII escapes for control characters, non-ASCII bytes, quotes and backslashes. The existing length limit is applied after escaping.
- Incomplete discovery is reported separately in the details, because additional installs may be missing from the total.
- With no attributed reasons, including when discovery stops before reaching any install, the generic three-cause sentence remains the fallback.
- Multisite safety limits keep their own account-specific warning. They do not count again in the summary or hide unrelated failures.
- Installation findings carry an opaque database scope. The host-wide coverage summary remains unscoped.

#### Which findings an incomplete scan keeps

| Case | What happens to findings |
|------|--------------------------|
| One installation completes while another fails | The complete installation scan retires its resolved findings. |
| An installation fails or is not discovered | It retains its findings. |
| An older finding has no database scope | It stays until reobserved or until the whole scanner completes. CSM does not guess its database from message text. |
| A multisite scan is partial | Findings are kept for its entire network. |
| Credential aliases share a database scope | All must complete before that scope can retire findings, regardless of scan order. |

The alias rule includes an alias whose database and table prefix are known but whose login credentials are missing.

Incomplete or interrupted scans protect earlier findings from eviction when new results fill the active list. That holds when every database or discovery attempt fails, the scanner times out, or an internal panic stops execution.

- The protection applies to findings already in the active list.
- Newly detected conditions compete for the remaining space under the normal priority order. Repeatedly incomplete scans therefore cannot grow the list beyond its cap.
- Retained findings can still refresh their details without losing their first observation.

#### Query errors

Query diagnostics include the detector stage, failure class and numeric MySQL error code. Repeated errors are counted together, with bounded detail when many causes occur. Raw SQL, server error messages and credentials are never included.

| Error | Effect |
|-------|--------|
| A known statement error, such as a missing table or column | The scan is incomplete, but independent detectors continue. |
| A server regular-expression timeout | A statement-local failure. Independent checks continue. The failed check keeps coverage incomplete and preserves earlier findings. |
| A connection, authentication or unknown failure | Further queries for that database stop. |

#### Hidden-link selection

- Selection examines only the leading and trailing parts of each value that the parser reads, so large values cost no more than the parsed sample.
- When the parser joins those parts into a complete value, selection examines them together too.
- Ordinary CSS declarations are matched with literal searches. Guarded expressions handle commented and encoded styles without admitting unrelated page text.
- Comment bodies are preserved during matching, so normalization cannot change their meaning.
- If the server stops a regular expression, the selection is repeated without commented styles. Plain and encoded styles stay covered, and the coverage gap is still reported.

### CMS database scan limits

These rules apply to the Joomla, Drupal, Magento, OpenCart, and PrestaShop scans.

Configuration reads:

- They accept regular files up to 1 MiB.
- Configuration symlinks and special files are rejected, including during Joomla, OpenCart, and PrestaShop marker probes. Drupal's version marker must also be a regular file.
- Reads use the opened file throughout, reject changes observed during the read, and stop when the scan is canceled.
- Read failures and missing required credentials mark that CMS scan incomplete.
- A manual re-check keeps the finding unresolved when its configuration cannot be inspected.

Incomplete scans:

- Database errors, discovery errors, and configuration or query limits keep the affected CMS check incomplete.
- Earlier findings remain until that CMS completes a scan. Another CMS can still complete and clear its own resolved findings.

Queries:

- Queries inspect at most 200 rows and request one extra row to detect overflow.
- Known statement errors and overflow allow independent queries to continue.
- Connection failures and cancellation stop further queries for that installation.

### Companion sweep limits

These limits apply to the sweeps described in [Files Planted Alongside Malware](#files-planted-alongside-malware).

- Each plant window of a directory and owner is swept once a day at most. Another member of the same kit, a repeated alert or the quarantine of the detected file does not sweep it again.
- Sweeps run one at a time. They share the scan concurrency limit and per-check execution deadline with periodic checks.
- Matches are delivered in batches, and the scan slot is released while waiting for delivery.
- Overlapping windows do not repeat content findings for the same file version.
- However often a file is detected, CSM keeps one recorded version of it. Expired records are removed even when no new work arrives.
- A sweep that is still waiting for its window to close keeps its once-a-day claim until it runs.
- The `.htaccess` audit counts the PHP files beside an `.htaccess` once, reading the directory in batches. It stops when the scan is canceled or as soon as it has counted enough files to decide.

### YARA worker error logging

Repeated YARA worker buffer-scan failures are logged at most once per minute per tracked error. When the error recurs after that window, the log reports the suppressed count.

If many distinct failures exhaust the tracking limit, additional errors share a bounded summary and do not reset suppression. Scan errors still reach callers and preserve incomplete-scan reporting.
